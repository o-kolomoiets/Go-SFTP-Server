// SPDX-License-Identifier: Apache-2.0

// Package supervisor is the part of gosftpd-gui that runs gosftpd (ADR
// 0013). It knows no toolkit: the window calls it and shows what it
// returns.
//
// The GUI never links the server's packages and never writes or parses
// the configuration's TOML. It runs the gosftpd shipped with it:
//   - init --force writes the configuration, and user add, set, disable,
//     enable and remove change the people (Admin);
//   - config show --json and user list --json read them back;
//   - serve --print-details --stop-on-stdin-eof runs the server, and its
//     first line on stdout says how to connect or why it did not start
//     (Server);
//   - the audit log says who is connected and what was transferred
//     (Follower, Activity).
//
// Every action of the GUI is thus a gosftpd command, which a person can
// type too.
package supervisor
