// Monitor-admin is root's client of the monitor's opt-in administrative
// socket (internal/admin).
//
//	barmkin monitor-admin list  [-admin-socket PATH] [-json]
//	barmkin monitor-admin clear -uid UID -host HOST -lineage ID -reason REASON
//	                            [-admin-socket PATH]
//
// list prints every lineage: its opaque id, uid, host, epoch, legs and the
// closed sources that raised them, when, its sessions and its past clears.
// clear clears one lineage, named exactly. It must be run by root from a
// terminal: it shows the lineage, warns that clearing monitor state does not
// remove untrusted material already in the AI conversation, and clears only
// when the operator types the lineage id back. The reason is one of the
// closed reason codes. Both refuse to talk to a socket that is not root's in
// a directory only root can enter. They exit 0 on success, 1 on failure and
// 2 on a usage error.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Daviey/barmkin/internal/admin"
	"github.com/Daviey/barmkin/internal/journal"
	imonitor "github.com/Daviey/barmkin/internal/monitor"
	"github.com/Daviey/barmkin/internal/proto"
)

// conversationWarning is shown before and after every clear.
const conversationWarning = `Clearing monitor state does not remove untrusted material already in an AI
conversation. Anything the session read, a prompt injection included, stays
in its context and can still steer it after the clear.`

// adminEnv is what monitor-admin runs against, replaceable in tests.
type adminEnv struct {
	stdin       *os.File
	stdout      io.Writer
	stderr      io.Writer
	euid        int
	isTerminal  func(*os.File) bool
	socketOwner int // the uid the socket and its directory must belong to: root
}

func cmdMonitorAdmin(args []string) {
	os.Exit(runMonitorAdmin(args, adminEnv{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		euid: os.Geteuid(), isTerminal: isTerminal, socketOwner: 0,
	}))
}

func runMonitorAdmin(args []string, env adminEnv) int {
	if len(args) == 0 {
		return adminUsage(env, "")
	}
	switch args[0] {
	case "list":
		return adminList(args[1:], env)
	case "clear":
		return adminClear(args[1:], env)
	}
	return adminUsage(env, "unknown command "+strconv.Quote(args[0]))
}

func adminUsage(env adminEnv, problem string) int {
	if problem != "" {
		fmt.Fprintf(env.stderr, "[barmkin monitor-admin] %s\n", problem)
	}
	fmt.Fprintf(env.stderr, `Usage:
  barmkin monitor-admin list  [-admin-socket PATH] [-json]
  barmkin monitor-admin clear -uid UID -host HOST -lineage ID -reason REASON [-admin-socket PATH]

Run as root. clear needs a terminal and asks you to type the lineage id back.
Hosts: %s, %s. Reasons: %s.
`, proto.HostClaudeCode, proto.HostOpenCode, joinReasons())
	return 2
}

func joinReasons() string {
	var rs []string
	for _, r := range journal.Reasons {
		rs = append(rs, string(r))
	}
	return strings.Join(rs, ", ")
}

func adminFailf(env adminEnv, format string, args ...any) int {
	fmt.Fprintf(env.stderr, "[barmkin monitor-admin] "+format+"\n", args...)
	return 1
}

// adminClient checks that the caller is root and the socket is root's, and
// only then returns a client of it.
func adminClient(env adminEnv, socket string) (*admin.Client, error) {
	if env.euid != 0 {
		return nil, errors.New("must be run by root")
	}
	if err := admin.CheckSocket(socket, env.socketOwner); err != nil {
		return nil, fmt.Errorf("refusing the administrative socket: %w", err)
	}
	return admin.NewClient(socket), nil
}

func adminList(args []string, env adminEnv) int {
	fs := flag.NewFlagSet("monitor-admin list", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	socket := fs.String("admin-socket", imonitor.DefaultAdminSocket, "the monitor's administrative socket")
	asJSON := fs.Bool("json", false, "print the list as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		return adminUsage(env, "unexpected argument "+strconv.Quote(fs.Arg(0)))
	}
	c, err := adminClient(env, *socket)
	if err != nil {
		return adminFailf(env, "%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), admin.Deadline)
	defer cancel()
	list, err := c.List(ctx)
	if err != nil {
		return adminFailf(env, "list: %v", err)
	}
	if *asJSON {
		out, _ := json.MarshalIndent(list, "", "  ")
		fmt.Fprintln(env.stdout, string(out))
		return 0
	}
	tw := tabwriter.NewWriter(env.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LINEAGE\tUID\tHOST\tEPOCH\tUNTRUSTED\tSENSITIVE\tSESSIONS\tCLEARS")
	for _, l := range list.Lineages {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%s\t%s\t%d\t%d\n", l.Lineage, l.UID, l.Host, l.Epoch,
			leg(l.Legs.Untrusted, l.UntrustedAt), leg(l.Legs.Sensitive, l.SensitiveAt), len(l.Sessions), len(l.Clears))
	}
	tw.Flush()
	return 0
}

// leg shows a leg's source and when it rose.
func leg(source proto.Source, at int64) string {
	if source == proto.SourceNone {
		return string(source)
	}
	return string(source) + " (" + when(at) + ")"
}

func when(at int64) string {
	if at == 0 {
		return "time unknown"
	}
	return time.Unix(at, 0).UTC().Format(time.RFC3339)
}

func adminClear(args []string, env adminEnv) int {
	fs := flag.NewFlagSet("monitor-admin clear", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	socket := fs.String("admin-socket", imonitor.DefaultAdminSocket, "the monitor's administrative socket")
	uidFlag := fs.String("uid", "", "the uid of the lineage's client")
	host := fs.String("host", "", "the lineage's host: "+string(proto.HostClaudeCode)+" or "+string(proto.HostOpenCode))
	lineage := fs.String("lineage", "", "the lineage's id: its root session's token")
	reason := fs.String("reason", "", "why: "+joinReasons())
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		return adminUsage(env, "unexpected argument "+strconv.Quote(fs.Arg(0)))
	}
	uid, err := strconv.ParseUint(*uidFlag, 10, 32)
	switch {
	case err != nil:
		return adminUsage(env, "-uid must be a uid number")
	case !admin.ValidHost(proto.Host(*host)):
		return adminUsage(env, "-host must be "+string(proto.HostClaudeCode)+" or "+string(proto.HostOpenCode))
	case !proto.ValidToken(*lineage):
		return adminUsage(env, "-lineage must be a lineage id, as list prints it")
	case !journal.ValidReason(journal.Reason(*reason)):
		return adminUsage(env, "-reason must be one of: "+joinReasons())
	}
	// A clear is typed by a person: never from a pipe, a script or an agent.
	if !env.isTerminal(env.stdin) {
		return adminFailf(env, "clear needs a terminal on standard input, so that a person confirms it; nothing was cleared")
	}
	c, err := adminClient(env, *socket)
	if err != nil {
		return adminFailf(env, "%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), admin.Deadline)
	list, err := c.List(ctx)
	cancel()
	if err != nil {
		return adminFailf(env, "list: %v", err)
	}
	i := slices.IndexFunc(list.Lineages, func(l admin.Lineage) bool {
		return l.UID == uint32(uid) && l.Host == proto.Host(*host) && l.Lineage == *lineage
	})
	if i < 0 {
		for _, l := range list.Lineages {
			if l.UID == uint32(uid) && l.Host == proto.Host(*host) &&
				slices.ContainsFunc(l.Sessions, func(s admin.Session) bool { return s.Session == *lineage }) {
				return adminFailf(env, "%s is a session of lineage %s, not a lineage; name the lineage. Nothing was cleared", *lineage, l.Lineage)
			}
		}
		return adminFailf(env, "no lineage %s for uid %d on %s; nothing was cleared", *lineage, uid, *host)
	}
	l := list.Lineages[i]

	out := env.stdout
	fmt.Fprintf(out, "Lineage    %s\nUid        %d\nHost       %s\nEpoch      %d\n", l.Lineage, l.UID, l.Host, l.Epoch)
	fmt.Fprintf(out, "Untrusted  %s\nSensitive  %s\n", leg(l.Legs.Untrusted, l.UntrustedAt), leg(l.Legs.Sensitive, l.SensitiveAt))
	fmt.Fprintf(out, "Sessions   %d\nPast clears %d\nReason     %s\n\n", len(l.Sessions), len(l.Clears), *reason)
	fmt.Fprintf(out, "%s\n\nClearing lowers both legs, starts epoch %d and makes every session of this\nlineage register again. The cleared legs stay in the journal.\n\n", conversationWarning, l.Epoch+1)
	fmt.Fprint(out, "Type the lineage id to clear it, or anything else to cancel: ")
	typed, err := bufio.NewReader(io.LimitReader(env.stdin, 1024)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return adminFailf(env, "read confirmation: %v; nothing was cleared", err)
	}
	if strings.TrimRight(typed, "\r\n") != l.Lineage {
		fmt.Fprintln(out)
		return adminFailf(env, "the lineage id was not typed back; nothing was cleared")
	}

	ctx, cancel = context.WithTimeout(context.Background(), admin.Deadline)
	defer cancel()
	resp, err := c.Clear(ctx, admin.ClearRequest{UID: l.UID, Host: l.Host, Lineage: l.Lineage, Epoch: l.Epoch, Legs: l.Legs, Reason: journal.Reason(*reason)})
	if ae, ok := errors.AsType[*admin.Error](err); ok && ae.Code == admin.CodeMismatch {
		return adminFailf(env, "the lineage changed after it was shown; nothing was cleared. Run clear again to see it as it is now")
	}
	if err != nil {
		return adminFailf(env, "clear: %v; the lineage may not have been cleared, so list it before trying again", err)
	}
	fmt.Fprintf(out, "Cleared. Lineage %s is in epoch %d with legs untrusted=%s sensitive=%s.\nIts sessions must register again before their next call.\n\n%s\n",
		resp.Lineage.Lineage, resp.Lineage.Epoch, resp.Lineage.Legs.Untrusted, resp.Lineage.Legs.Sensitive, conversationWarning)
	return 0
}
