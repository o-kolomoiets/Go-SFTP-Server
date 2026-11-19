// SPDX-License-Identifier: Apache-2.0

//go:build unix

package qtui

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	qt "github.com/mappu/miqt/qt6"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// People and folders once a folder was shared (M5b-04): every change is
// a gosftpd command, run at once, and read by gosftpd at once while it
// shares (ADR 0013, "Lifecycle").

// personRow is a person in the list.
type personRow struct {
	p        supervisor.Person
	w        *qt.QWidget
	access   *qt.QPushButton
	password *qt.QPushButton
	toggle   *qt.QPushButton // Disable or Enable
	remove   *qt.QPushButton
}

// permChoice is a choice of what a person may do in a folder: a
// permission preset of gosftpd, or none.
type permChoice struct{ value, label string }

var permChoices = []permChoice{
	{"", "No access"},
	{"read", "Read: download files"},
	{"upload", "Upload: add new files"},
	{"readwrite", "Read and write: download, upload, replace"},
	{"full", "Full: also delete"},
}

// includes reports whether permissions a allow at least what b does, for
// gosftpd's presets: full covers all, readwrite covers read and upload.
func includes(a, b string) bool {
	switch {
	case a == b, b == "":
		return true
	case a == "full":
		return slices.Contains([]string{"read", "upload", "readwrite"}, b)
	case a == "readwrite":
		return b == "read" || b == "upload"
	}
	return false
}

// narrows reports whether access after takes anything away that before
// gave.
func narrows(before, after map[string]string) bool {
	for folder, p := range before {
		if !includes(after[folder], p) {
			return true
		}
	}
	return false
}

// pathsMove says how the person's paths change when their folders go
// from before to after, "" when they do not: gosftpd shows a person with
// one folder its files at the top, and a person with more each folder as
// a directory (ADR 0013, "Lifecycle").
func pathsMove(name string, before, after map[string]string) string {
	if len(before) == 0 || len(after) == 0 || (len(before) == 1) == (len(after) == 1) {
		return ""
	}
	if len(before) == 1 {
		folder := slices.Collect(maps.Keys(before))[0]
		return fmt.Sprintf("%s's files in %s move from the top to a directory: /report.pdf becomes /%s/report.pdf. Tell them, or their programs will not find the old paths.", name, folder, folder)
	}
	folder := slices.Collect(maps.Keys(after))[0]
	return fmt.Sprintf("%s keeps only %s, whose files move to the top: /%s/report.pdf becomes /report.pdf. Tell them, or their programs will not find the old paths.", name, folder, folder)
}

// onConflictChoices are the values of on_conflict in the order of their
// combo box, with what they mean.
var onConflictChoices = []permChoice{
	{"rename", "Keep both: the new file gets another name"},
	{"reject", "Refuse the upload"},
	{"overwrite", "Replace the old file"},
	{"version", "Replace it and keep the old one as a version"},
}

// showPeople lists the people of the configuration with what each may do.
func (w *Window) showPeople() {
	for _, r := range w.peopleRows {
		r.w.Hide()
		r.w.DeleteLater()
	}
	w.peopleRows = nil
	if len(w.cur.People) == 0 {
		w.people.SetText("Add the person who may connect.")
	} else {
		w.people.SetText("These people may connect. Add someone else below.")
	}
	for _, p := range w.cur.People {
		w.addPersonRow(p)
	}
	w.updateEnabled()
}

func (w *Window) addPersonRow(p supervisor.Person) {
	r := &personRow{p: p, w: qt.NewQWidget2()}
	l := qt.NewQHBoxLayout2()
	l.SetContentsMargins(0, 0, 0, 0)
	r.w.SetLayout(l.QLayout)
	label := qt.NewQLabel3(personText(p))
	label.SetWordWrap(true)
	l.AddWidget2(label.QWidget, 1)
	r.access = qt.NewQPushButton3("Access…")
	r.access.SetAccessibleName("Access of " + p.Name)
	r.access.OnClicked(func() { w.editAccess(r.p) })
	r.password = qt.NewQPushButton3("Password…")
	r.password.SetAccessibleName("New password for " + p.Name)
	r.password.OnClicked(func() { w.newPassword(r.p) })
	if p.Status == "disabled" {
		r.toggle = qt.NewQPushButton3("Enable")
		r.toggle.SetAccessibleName("Enable " + p.Name)
	} else {
		r.toggle = qt.NewQPushButton3("Disable")
		r.toggle.SetAccessibleName("Disable " + p.Name)
	}
	r.toggle.OnClicked(func() { w.toggle(r.p) })
	r.remove = qt.NewQPushButton3("Remove")
	r.remove.SetAccessibleName("Remove " + p.Name)
	r.remove.OnClicked(func() { w.removePerson(r.p) })
	for _, b := range []*qt.QPushButton{r.access, r.password, r.toggle, r.remove} {
		l.AddWidget(b.QWidget)
	}
	w.peopleBox.AddWidget(r.w)
	w.peopleRows = append(w.peopleRows, r)
}

// personText is a person as the list shows them: name, how they sign in,
// what they may do, and whether they are disabled.
func personText(p supervisor.Person) string {
	var how []string
	if p.Password {
		how = append(how, "password")
	}
	if p.Keys > 0 {
		how = append(how, "public key")
	}
	if len(how) == 0 {
		how = append(how, "no way to sign in")
	}
	access := "no folder"
	if len(p.Access) > 0 {
		parts := make([]string, 0, len(p.Access))
		for _, folder := range slices.Sorted(maps.Keys(p.Access)) {
			parts = append(parts, folder+": "+p.Access[folder])
		}
		access = strings.Join(parts, ", ")
	}
	s := fmt.Sprintf("%s (%s). %s", p.Name, strings.Join(how, " or "), access)
	if p.Status == "disabled" {
		s += ". Disabled"
	}
	return s
}

// editAccess asks what the person may do in each folder.
func (w *Window) editAccess(p supervisor.Person) {
	dlg := qt.NewQDialog(w.win.QWidget)
	dlg.SetWindowTitle("Access of " + p.Name)
	l := qt.NewQVBoxLayout2()
	dlg.SetLayout(l.QLayout)
	intro := qt.NewQLabel3(fmt.Sprintf("What %s may do in each folder:", p.Name))
	intro.SetWordWrap(true)
	l.AddWidget(intro.QWidget)
	form := qt.NewQFormLayout2()
	combos := map[string]*qt.QComboBox{}
	values := map[string][]string{}
	for _, f := range w.cur.Settings.Folders {
		c := qt.NewQComboBox2()
		var vals []string
		for _, ch := range permChoices {
			c.AddItem(ch.label)
			vals = append(vals, ch.value)
		}
		cur := p.Access[f.Name]
		i := slices.Index(vals, cur)
		if i < 0 { // set by hand: kept unless changed
			c.AddItem("As set by hand: " + cur)
			vals = append(vals, cur)
			i = len(vals) - 1
		}
		c.SetCurrentIndex(i)
		c.SetAccessibleName(f.Name)
		form.AddRow3(f.Name+":", c.QWidget)
		combos[f.Name], values[f.Name] = c, vals
	}
	l.AddLayout(form.QLayout)
	buttons := qt.NewQDialogButtonBox7(qt.QDialogButtonBox__Ok|qt.QDialogButtonBox__Cancel, dlg.QWidget)
	buttons.OnAccepted(dlg.Accept)
	buttons.OnRejected(dlg.Reject)
	l.AddWidget(buttons.QWidget)
	ok := dlg.Exec() == int(qt.QDialog__Accepted)
	access := map[string]string{}
	for name, c := range combos {
		if v := values[name][c.CurrentIndex()]; v != "" {
			access[name] = v
		}
	}
	dlg.DeleteLater()
	if ok {
		w.applyAccess(p, access)
	}
}

// applyAccess writes what the person may do: folder name to permissions.
func (w *Window) applyAccess(p supervisor.Person, access map[string]string) {
	if maps.Equal(access, p.Access) {
		return
	}
	if move := pathsMove(p.Name, p.Access, access); move != "" && !w.confirm("Change the paths of "+p.Name+"?", move) {
		return
	}
	var narrowed []string
	if narrows(p.Access, access) {
		narrowed = []string{p.Name}
	}
	w.change(fmt.Sprintf("Changed what %s may do.", p.Name), narrowed, func(ctx context.Context) (app.Change, error) {
		return w.app.SetAccess(ctx, p.Name, access)
	})
}

// newPassword asks for a new password for the person, typed or generated.
func (w *Window) newPassword(p supervisor.Person) {
	dlg := qt.NewQDialog(w.win.QWidget)
	dlg.SetWindowTitle("New password for " + p.Name)
	l := qt.NewQVBoxLayout2()
	dlg.SetLayout(l.QLayout)
	note := qt.NewQLabel3(fmt.Sprintf("The new password for %s. A public key they have keeps working.", p.Name))
	note.SetWordWrap(true)
	l.AddWidget(note.QWidget)
	row := qt.NewQHBoxLayout2()
	field := qt.NewQLineEdit2()
	field.SetEchoMode(qt.QLineEdit__Password)
	field.SetAccessibleName("New password")
	gen := qt.NewQPushButton3("Generate…")
	gen.SetAccessibleName("Generate a password")
	gen.OnClicked(func() {
		pw := supervisor.GeneratePassword()
		field.SetText(pw)
		w.showGenerated(p.Name, pw)
	})
	row.AddWidget(field.QWidget)
	row.AddWidget(gen.QWidget)
	l.AddLayout(row.QLayout)
	buttons := qt.NewQDialogButtonBox7(qt.QDialogButtonBox__Ok|qt.QDialogButtonBox__Cancel, dlg.QWidget)
	buttons.OnAccepted(dlg.Accept)
	buttons.OnRejected(dlg.Reject)
	l.AddWidget(buttons.QWidget)
	ok := dlg.Exec() == int(qt.QDialog__Accepted)
	pw := field.Text()
	field.SetText("")
	dlg.DeleteLater()
	if ok {
		w.applyPassword(p, pw)
	}
}

// applyPassword gives the person a new password.
func (w *Window) applyPassword(p supervisor.Person, pw string) {
	if err := supervisor.CheckPassword(pw); err != nil {
		w.fail(err.Error(), "")
		return
	}
	w.change(p.Name+" has a new password.", nil, func(ctx context.Context) (app.Change, error) {
		return w.app.SetPassword(ctx, p.Name, pw)
	})
}

// toggle disables or enables the person.
func (w *Window) toggle(p supervisor.Person) {
	if p.Status == "disabled" {
		w.change(p.Name+" may log in again.", nil, func(ctx context.Context) (app.Change, error) {
			return w.app.Enable(ctx, p.Name)
		})
		return
	}
	w.change(p.Name+" may no longer log in.", nil, func(ctx context.Context) (app.Change, error) {
		return w.app.Disable(ctx, p.Name)
	})
}

func (w *Window) removePerson(p supervisor.Person) {
	if !w.confirm("Remove "+p.Name+"?", p.Name+" may no longer log in, and their connections end. To let them in again, add them again.") {
		return
	}
	w.change(fmt.Sprintf("Removed %s.", p.Name), nil, func(ctx context.Context) (app.Change, error) {
		return w.app.Remove(ctx, p.Name)
	})
}

// addPerson adds the person of the form at once: they may use every
// folder, uploading where people may upload.
func (w *Window) addPerson() {
	f := w.form()
	p := f.Person
	if p.Name == "" && p.Password == "" && p.Key == "" {
		w.fail("Fill in the person's name, and a password or their public key.", "")
		w.name.SetFocus()
		return
	}
	access := f.Access()
	w.changeThen(fmt.Sprintf("Added %s.", p.Name), nil, func(ctx context.Context) (app.Change, error) {
		return w.app.AddPerson(ctx, p, access)
	}, func() {
		w.name.SetText("")
		w.password.SetText("")
		w.key.SetText("")
	})
}

// setFolders writes the folders at once; narrowed are the people the
// change takes something from.
func (w *Window) setFolders(folders []supervisor.Folder, done string, narrowed []string) {
	w.change(done, narrowed, func(ctx context.Context) (app.Change, error) {
		return w.app.SetFolders(ctx, folders)
	})
}

// listedFolders are the folders as the rows show them.
func (w *Window) listedFolders() []supervisor.Folder {
	out := make([]supervisor.Folder, 0, len(w.folders))
	for _, r := range w.folders {
		f := r.folder
		f.ReadOnly = r.access.CurrentIndex() == accessRead
		out = append(out, f)
	}
	return out
}

// folderAccessChanged writes a folder made read-only, or open to uploads.
func (w *Window) folderAccessChanged(r *folderRow) {
	if !w.cur.Configured {
		return
	}
	readOnly := r.access.CurrentIndex() == accessRead
	var narrowed []string
	if readOnly {
		for _, p := range w.cur.People {
			if perm := p.Access[r.folder.Name]; perm != "" && perm != "read" {
				narrowed = append(narrowed, p.Name)
			}
		}
	}
	done := r.folder.Name + " is read-only."
	if !readOnly {
		done = fmt.Sprintf("People may upload to %s, as what each may do allows.", r.folder.Name)
	}
	w.setFolders(w.listedFolders(), done, narrowed)
}

// removeSharedFolder stops sharing a folder of the configuration, after
// asking when people have it.
func (w *Window) removeSharedFolder(r *folderRow) {
	var who, moves []string
	for _, p := range w.cur.People {
		if _, ok := p.Access[r.folder.Name]; ok {
			who = append(who, p.Name)
			after := maps.Clone(p.Access)
			delete(after, r.folder.Name)
			if move := pathsMove(p.Name, p.Access, after); move != "" {
				moves = append(moves, move)
			}
		}
	}
	if len(who) > 0 && !w.confirm("Stop sharing "+r.folder.Name+"?",
		strings.Join(append([]string{fmt.Sprintf("%s lose%s access to %s. Its files stay where they are.",
			strings.Join(who, ", "), map[bool]string{true: "s"}[len(who) == 1], r.folder.Name)}, moves...), " ")) {
		return
	}
	var folders []supervisor.Folder
	for _, f := range w.listedFolders() {
		if f.Path != r.folder.Path {
			folders = append(folders, f)
		}
	}
	w.setFolders(folders, fmt.Sprintf("Stopped sharing %s.", r.folder.Name), who)
}

// setOnConflict writes what an upload to an existing file does.
func (w *Window) setOnConflict(i int) {
	if !w.cur.Configured || i < 0 || i >= len(onConflictChoices) {
		return
	}
	v := onConflictChoices[i].value
	if v == w.cur.Settings.OnConflict {
		return
	}
	w.change("Uploads to an existing file: "+strings.ToLower(onConflictChoices[i].label[:1])+onConflictChoices[i].label[1:]+".", nil,
		func(ctx context.Context) (app.Change, error) { return w.app.SetOnConflict(ctx, v) })
}

// change runs a change of the configuration off the main thread, reads
// the configuration again and shows what the change did. done says what
// it did; narrowed are the people it takes something from, who keep the
// old access while they are connected (ADR 0005).
func (w *Window) change(done string, narrowed []string, job func(context.Context) (app.Change, error)) {
	w.changeThen(done, narrowed, job, nil)
}

// changeThen is change, calling then once the change succeeded.
func (w *Window) changeThen(done string, narrowed []string, job func(context.Context) (app.Change, error), then func()) {
	w.busy = true
	wasSharing := w.state == sharing
	w.updateEnabled()
	w.setStatus("Saving…")
	w.run(func(ctx context.Context) func() {
		c, err := job(ctx)
		cur, loadErr := w.app.Load(ctx)
		return func() {
			w.busy = false
			if loadErr == nil {
				w.cur = cur
				w.showFolders()
				w.showPeople()
				w.refreshUser()
			}
			if err == nil && then != nil {
				then()
			}
			w.changed(done, narrowed, c, firstError(err, loadErr), wasSharing)
			w.afterChange()
		}
	})
}

// afterChange closes the window if it was closed while the change ran.
func (w *Window) afterChange() {
	if !w.quitDone {
		return
	}
	switch w.state {
	case sharing:
		w.stopSharing(false) // gosftpd's exit quits
	case idle:
		w.setState(idle) // quits
	case loading, working, stopping, restarting, broken:
		// A start, stop or restart under way quits when it ends.
	}
}

// changed shows what a change did: an error, a reload gosftpd refused, a
// restart it needs, or the people who keep their old access. wasSharing
// is whether gosftpd shared when the change began.
func (w *Window) changed(done string, narrowed []string, c app.Change, err error, wasSharing bool) {
	w.updateEnabled()
	if wasSharing && w.state != sharing {
		// gosftpd stopped, or stops, during the change: the status says
		// so, and stays.
		note := "Saved meanwhile: " + done + " It applies when sharing starts again."
		if err != nil {
			note = "The change made meanwhile failed: " + err.Error()
		}
		w.appendMore(joinNonEmpty(note, c.Warnings))
		return
	}
	if err != nil {
		summary := err.Error()
		switch {
		case c.Reloaded:
			summary += " gosftpd read what was saved before the error, and uses it already."
		case c.ReloadFailed != "":
			summary += fmt.Sprintf(" gosftpd also refused to read the configuration (%s) and keeps sharing as before.", c.ReloadFailed)
		}
		w.fail(summary, joinNonEmpty(c.Warnings, c.ReloadDetail))
		return
	}
	w.showMore(c.Warnings)
	if c.ReloadFailed != "" {
		w.fail(fmt.Sprintf("Saved, but gosftpd refused to read the change (%s) and keeps sharing as before. The change applies when sharing starts again.", c.ReloadFailed),
			joinNonEmpty(c.ReloadDetail, c.Warnings))
		return
	}
	msg := done
	if c.Disconnected > 0 {
		msg += fmt.Sprintf(" %d connection(s) of theirs ended.", c.Disconnected)
	}
	if w.state != sharing {
		w.setStatus(msg)
		return
	}
	// Who is connected now, not at the last poll: a restart without
	// asking only with nobody connected.
	w.pollActivity()
	var keep []string
	for _, n := range narrowed {
		if slices.Contains(w.who, n) {
			keep = append(keep, n)
		}
	}
	switch {
	case len(c.RestartRequired) > 0 && len(w.who) == 0:
		w.setStatus(msg + " The server starts again to apply it.")
		w.restart(false)
		return
	case len(c.RestartRequired) > 0:
		w.offerRestart = true
		msg += fmt.Sprintf(" It applies once the server starts again (%s). %s connected: Restart now applies it and may cut their transfers; otherwise it applies when you next start sharing.",
			strings.Join(c.RestartRequired, ", "), isAre(w.who))
	case len(keep) > 0:
		w.offerRestart = true
		msg += fmt.Sprintf(" %s keep%s the old access until they disconnect; Restart now applies it to them too.",
			strings.Join(keep, ", "), map[bool]string{true: "s"}[len(keep) == 1])
	}
	w.setStatus(msg)
	w.updateEnabled()
}

// refreshUser shows the connection details for another person when the
// one shown was removed or disabled.
func (w *Window) refreshUser() {
	if w.state != sharing || w.user == "" {
		return
	}
	if slices.ContainsFunc(w.cur.People, func(p supervisor.Person) bool { return p.Name == w.user && p.Status != "disabled" }) {
		return
	}
	w.user = userFor(app.Form{}, w.cur)
	w.fields["user"].SetText(w.user)
	w.fields["command"].SetText(w.shown.SFTPCommand(w.user))
}

// restart stops gosftpd and starts it again (Restart now). ask is true
// when the person pressed the button: with people connected, it asks
// first and names them.
func (w *Window) restart(ask bool) {
	if w.state != sharing {
		return
	}
	if ask && len(w.who) > 0 && !w.confirm("Restart now?",
		isAre(w.who)+" connected. The server waits up to 30 s for them to finish, then cuts their transfers.") {
		return
	}
	if w.state != sharing { // gosftpd exited while the question was open
		return
	}
	w.offerRestart = false
	w.setState(restarting)
	w.setStatus("Restarting the server…")
	user := w.user
	w.run(func(ctx context.Context) func() {
		d, err := w.app.Restart(ctx)
		return func() {
			if err != nil {
				w.poll.Stop()
				w.who = nil
				w.setState(idle)
				fmt.Fprintln(os.Stderr, "gosftpd-gui: restart:", err)
				w.startFailed(err, "")
				w.setStatus("Error: the server stopped to restart and did not start again. " + strings.TrimPrefix(w.status.Text(), "Error: "))
				return
			}
			w.started(d, user)
			if !w.quitDone {
				w.setStatus("The server started again with the changes.")
			}
		}
	})
}

// askYesNo asks a yes or no question: Window.confirm, which tests
// replace.
func (w *Window) askYesNo(title, text string) bool {
	return qt.QMessageBox_Question2(w.win.QWidget, title, text, qt.QMessageBox__Yes, qt.QMessageBox__No) == int(qt.QMessageBox__Yes)
}

// showGenerated shows a generated password once, to copy. The dialog,
// and so the password in plain text, goes when it closes.
func (w *Window) showGenerated(who, p string) {
	box := qt.NewQMessageBox6(qt.QMessageBox__Information, "Generated password",
		fmt.Sprintf("The password for %s is:\n\n%s\n\nSend it to them in a safe way. It is shown only now: gosftpd keeps only a hash of it.", who, p),
		qt.QMessageBox__Close, w.win.QWidget)
	box.SetTextInteractionFlags(qt.TextSelectableByMouse | qt.TextSelectableByKeyboard)
	box.SetInformativeText("Other programs can read what you copy.")
	copyButton := box.AddButton2("Copy password", qt.QMessageBox__ActionRole)
	box.Exec()
	if box.ClickedButton() != nil && box.ClickedButton().UnsafePointer() == copyButton.QAbstractButton.UnsafePointer() {
		qt.QGuiApplication_Clipboard().SetText(p)
		w.setStatus("Copied the password. Other programs can read what you copy.")
	}
	box.DeleteLater()
}
