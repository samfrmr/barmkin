// Package monitor is the barmkin monitor core: the service behind
// `barmkin monitor`, which answers the internal/proto contract on a Unix
// socket and keeps each session's taint in a crash-safe journal.
//
// # Sessions and legs
//
// A session is named by the client's uid (from the kernel's peer
// credentials), its host and its session token, so one user can never see
// or change another user's sessions. Each session belongs to a root
// lineage, named by the root token it registered with, and the lineage
// holds the two legs: untrusted (leg A) and sensitive (leg B). A subagent
// that registers under a root shares that root's legs.
//
// Legs only rise. observe raises the leg its source belongs to, and the
// first source to raise a leg stays. Nothing a client sends lowers a leg:
// the client contract has no clear, rotate, capability or acknowledgement
// operation, and registering again returns the legs unchanged and cannot
// move a session to another lineage. A session keeps its legs for the life
// of the monitor's state; a new session is a new registration. The only way
// down is root's opt-in administrative clear, below.
//
// # Administrative clear
//
// By default the monitor has no administrative socket and the taint is
// sticky. With [Config.AdminSocket], it also serves internal/admin on a
// socket that systemd creates, as root, in a directory only root can enter
// (barmkin-monitor-admin.socket), and passes to it by socket activation. The
// monitor never creates that socket: [Start] takes it from systemd, refuses
// to start without it, and requires its directory to be root's with no
// group or other access. The socket's server closes every connection whose
// peer is not root before reading it, and answers a request from any other
// uid forbidden. The client socket answers none of its paths, so no shim,
// plugin, MCP server, managed gate or ordinary user can reach it.
//
// list shows every lineage: its uid, host, root token, epoch, legs, the
// closed sources that raised them and when, its sessions, and its earlier
// clears. clear lowers both legs of one lineage named exactly, with the
// epoch and legs root was shown and a closed reason. The monitor appends a
// clear record starting the lineage's next epoch and answers only after the
// journal's fsync returns; until then the legs stay up, and a clear the
// journal cannot take degrades the monitor and lowers nothing. The cleared
// raises stay in the journal and in the lineage's history, and compaction
// keeps them. Every pre-registration of the lineage's sessions is dropped,
// and each session is unknown_session until it registers again in the new
// epoch, which the shims do on that error. A clear survives a clean restart;
// after an unclean one, monitor_restart raises the untrusted leg again, as
// for every lineage.
//
// Clearing monitor state does not remove untrusted material already in an
// AI conversation: anything the session read, a prompt injection included,
// is still in its context. barmkin monitor-admin, the client, says so and
// asks root to type the lineage back from a terminal before it clears.
//
// # Unknown and unrecoverable sessions deny
//
// Every operation on a session the monitor has not registered fails with
// unknown_session, which clients treat as a deny. Registering a session in
// a lineage the monitor has never seen starts it clean only when the host
// reports a fresh top-level session; any other new lineage starts with its
// untrusted leg raised by unknown_session, because its history is not
// known to be clean. That covers a monitor installed mid-session, a
// deleted journal, and a session whose records were lost.
//
// When the last run did not stop cleanly (a crash, a kill, a torn or
// damaged journal), a request it accepted may have been lost, so every
// lineage it knew starts with its untrusted leg raised by monitor_restart.
// A damaged journal is moved aside as journal.damaged-<time>, and only
// the records that still pass their checks are replayed. A private regular
// journal that cannot be read or is over the size limit is moved aside the
// same way, and every session then starts unknown. A symlink, a
// non-regular file or a journal with the wrong owner or mode is never
// followed or moved, and the monitor refuses to start. If a change
// cannot be journaled, the monitor degrades: health reports degraded and
// every other operation fails unavailable until it is restarted.
//
// # Decisions
//
// decide follows barmkin-mod's decideEgress over a class postures table
// versioned with the monitor: in a clean lineage only the destructive
// classes warn; with the untrusted leg up the classes that deny on it are
// denied and the rest warn; with both legs up every class is denied (the
// Rule of Two). The sensitive leg alone denies nothing.
//
// preregister and gate implement the managed gate's per-call presence: a
// pre-registration lives for the configured lifetime and admits one gate
// check. Pre-registrations are held in memory only, so a restart drops
// them and the gate denies.
//
// The monitor core has no classifier. screen raises the untrusted leg for
// the content's source and answers unavailable, which the shim treats as a
// deny; the windows are never read, kept or echoed. status reports the
// classifier as degraded.
//
// # Posture
//
// register refuses, with posture_refused, a host that does not run its
// tools in a sandbox or whose sandbox allows every Unix socket, since a
// sandboxed tool could then reach this socket itself. A refused register
// creates no session. Reporting the posture is the shim's job; the
// managed settings that register the shim and the gate are the contract
// boundary.
//
// # Deployment
//
// The monitor is installed and managed by root and runs as a dedicated
// service user. Root creates both directories it uses, for example with a
// systemd unit that sets User=, StateDirectory= and RuntimeDirectory=:
//
//	/var/lib/barmkin     state directory, owned by the service user, 0700
//	/run/barmkin         runtime directory, owned by the service user, 0750,
//	                     group barmkin-clients
//
// [Start] refuses to run as root, requires both directories to exist with
// those owners and no more than those modes, requires every directory above
// them to be owned by root or the service user and writable by nobody else,
// and refuses symlinks. It holds an exclusive lock on the state directory
// for its life. The journal is 0600. The socket is created 0660, group
// barmkin-clients; the service user must be a member of that group, and so
// must each user whose agent hosts may connect.
//
// The server reads each connection's peer credentials and closes any
// connection it cannot identify. A Go client can pin the service user with
// [DialPinned]; the TypeScript shims cannot, which is a known residual.
//
// # Telemetry
//
// With [Config.Telemetry] set from root's configuration, the monitor
// exports each journaled change, content-free, through internal/telemetry.
// A change is handed over only after its append returned, and the hand-off
// never blocks, so the export cannot delay, reorder or change an answer or
// an fsync. The journal stays the authoritative record.
package monitor
