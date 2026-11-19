// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Package qtui is the window of gosftpd-gui in Qt 6 Widgets through miqt:
// the only package that knows the toolkit (ADR 0013). What the window
// does is in package app; this package lays it out and runs app's calls
// off the Qt main thread, which keeps every widget.
package qtui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// state is what the window is doing.
type state int

const (
	loading  state = iota // reading the configuration
	idle                  // not sharing
	working               // writing the configuration, starting gosftpd
	sharing               // gosftpd serves
	stopping              // gosftpd stops
	broken                // the configuration could not be read: nothing may change it
)

// Options are the window's command-line options.
type Options struct {
	// StartSharing starts sharing once the configuration is read, as the
	// Start sharing button does, if a folder was shared before.
	StartSharing bool
}

// Window is the main window: the "Share a folder" screen.
type Window struct {
	app  *app.App
	opts Options
	win  *qt.QMainWindow

	folders     []*folderRow
	folderRows  *qt.QVBoxLayout
	noFolder    *qt.QLabel
	addFolder   *qt.QPushButton
	people      *qt.QLabel
	name        *qt.QLineEdit
	usePassword *qt.QRadioButton
	useKey      *qt.QRadioButton
	password    *qt.QLineEdit
	generate    *qt.QPushButton
	key         *qt.QLineEdit
	port        *qt.QSpinBox

	start   *qt.QPushButton
	stop    *qt.QPushButton
	stopNow *qt.QPushButton

	details   *qt.QGroupBox
	fields    map[string]*qt.QLineEdit
	connected *qt.QLabel
	status    *qt.QLabel
	more      *qt.QPlainTextEdit
	poll      *qt.QTimer

	cur      app.Current
	state    state
	user     string   // the user of the connection details
	who      []string // who is connected, as last shown
	quitDone bool     // quit once gosftpd has exited
	// closing is set when the window is closed while a start is under
	// way, for the job off the main thread not to start gosftpd.
	closing atomic.Bool
}

// folderRow is a shared folder in the list.
type folderRow struct {
	folder supervisor.Folder
	w      *qt.QWidget
	access *qt.QComboBox
	remove *qt.QPushButton
}

// Access choices of a folder, in the order of its combo box.
const (
	accessUpload = iota
	accessRead
)

// detail is a line of the connection details, with the accessible name
// of its Copy button.
type detail struct{ key, label string }

var detailLines = []detail{
	{"host", "Host"},
	{"port", "Port"},
	{"user", "User"},
	{"fingerprint", "Host key fingerprint"},
	{"known_hosts", "known_hosts line"},
	{"command", "Command"},
}

// New builds the window for a. It reads the configuration once it is
// shown.
func New(a *app.App, opts Options) *Window {
	w := &Window{app: a, opts: opts, fields: map[string]*qt.QLineEdit{}}
	w.win = qt.NewQMainWindow2()
	w.win.SetWindowTitle("gosftpd: share a folder")
	central := qt.NewQWidget2()
	page := qt.NewQVBoxLayout2()
	central.SetLayout(page.QLayout)
	w.win.SetCentralWidget(central)

	intro := qt.NewQLabel3("Share folders on this computer with people you choose. " +
		"They connect with an SFTP program, such as FileZilla, WinSCP or sftp, using the details shown once sharing starts.")
	intro.SetWordWrap(true)
	page.AddWidget(intro.QWidget)

	page.AddWidget(w.buildFolders().QWidget)
	page.AddWidget(w.buildPeople().QWidget)
	page.AddWidget(w.buildServer().QWidget)

	buttons := qt.NewQHBoxLayout2()
	w.start = qt.NewQPushButton3("Start sharing")
	w.start.OnClicked(w.startSharing)
	w.stop = qt.NewQPushButton3("Stop sharing")
	w.stop.OnClicked(func() { w.stopSharing(false) })
	w.stopNow = qt.NewQPushButton3("Stop now")
	w.stopNow.SetAccessibleDescription("Ends the connections still open")
	w.stopNow.OnClicked(func() { w.stopSharing(true) })
	buttons.AddWidget(w.start.QWidget)
	buttons.AddWidget(w.stop.QWidget)
	buttons.AddWidget(w.stopNow.QWidget)
	buttons.AddStretch()
	page.AddLayout(buttons.QLayout)

	page.AddWidget(w.buildDetails().QWidget)

	w.status = qt.NewQLabel2()
	w.status.SetWordWrap(true)
	w.status.SetTextInteractionFlags(qt.TextSelectableByMouse | qt.TextSelectableByKeyboard)
	page.AddWidget(w.status.QWidget)
	w.more = qt.NewQPlainTextEdit2()
	w.more.SetReadOnly(true)
	w.more.SetAccessibleName("Details of the last message")
	w.more.SetVisible(false)
	page.AddWidget(w.more.QWidget)
	page.AddStretch()

	w.poll = qt.NewQTimer2(w.win.QObject)
	w.poll.OnTimeout(w.pollActivity)

	w.win.OnCloseEvent(w.closeEvent)
	w.setState(loading)
	return w
}

func (w *Window) buildFolders() *qt.QGroupBox {
	box := qt.NewQGroupBox3("Folders")
	l := qt.NewQVBoxLayout2()
	box.SetLayout(l.QLayout)
	w.noFolder = qt.NewQLabel3("No folder yet: add the folder people may upload to or read from.")
	w.noFolder.SetWordWrap(true)
	l.AddWidget(w.noFolder.QWidget)
	w.folderRows = qt.NewQVBoxLayout2()
	l.AddLayout(w.folderRows.QLayout)
	hint := qt.NewQLabel3("With one folder, people see its files at the top. With more, each folder is a directory with the name shown.")
	hint.SetWordWrap(true)
	l.AddWidget(hint.QWidget)
	w.addFolder = qt.NewQPushButton3("Add folder…")
	w.addFolder.OnClicked(w.chooseFolder)
	row := qt.NewQHBoxLayout2()
	row.AddWidget(w.addFolder.QWidget)
	row.AddStretch()
	l.AddLayout(row.QLayout)
	return box
}

func (w *Window) buildPeople() *qt.QGroupBox {
	box := qt.NewQGroupBox3("People")
	l := qt.NewQVBoxLayout2()
	box.SetLayout(l.QLayout)
	w.people = qt.NewQLabel2()
	w.people.SetWordWrap(true)
	l.AddWidget(w.people.QWidget)

	form := qt.NewQFormLayout2()
	w.name = qt.NewQLineEdit2()
	w.name.SetAccessibleName("Name")
	w.name.SetPlaceholderText("for example partner")
	form.AddRow3("Name:", w.name.QWidget)

	how := qt.NewQHBoxLayout2()
	w.usePassword = qt.NewQRadioButton3("Password")
	w.useKey = qt.NewQRadioButton3("Public key")
	w.usePassword.SetChecked(true)
	w.usePassword.OnToggled(func(bool) { w.updateEnabled() })
	how.AddWidget(w.usePassword.QWidget)
	how.AddWidget(w.useKey.QWidget)
	how.AddStretch()
	form.AddRow4("Signs in with:", how.QLayout)

	pw := qt.NewQHBoxLayout2()
	w.password = qt.NewQLineEdit2()
	w.password.SetEchoMode(qt.QLineEdit__Password)
	w.password.SetAccessibleName("Password")
	w.generate = qt.NewQPushButton3("Generate…")
	w.generate.SetAccessibleName("Generate a password")
	w.generate.OnClicked(w.generatePassword)
	pw.AddWidget(w.password.QWidget)
	pw.AddWidget(w.generate.QWidget)
	form.AddRow4("Password:", pw.QLayout)

	w.key = qt.NewQLineEdit2()
	w.key.SetAccessibleName("Public key")
	w.key.SetPlaceholderText("ssh-ed25519 AAAA… (their public key, never a private key)")
	form.AddRow3("Public key:", w.key.QWidget)
	l.AddLayout(form.QLayout)
	return box
}

func (w *Window) buildServer() *qt.QGroupBox {
	box := qt.NewQGroupBox3("Server")
	form := qt.NewQFormLayout2()
	box.SetLayout(form.QLayout)
	w.port = qt.NewQSpinBox2()
	w.port.SetRange(1, 65535)
	w.port.SetValue(app.DefaultPort)
	w.port.SetAccessibleName("Port")
	w.port.SetMaximumWidth(120)
	form.AddRow3("Port:", w.port.QWidget)
	return box
}

func (w *Window) buildDetails() *qt.QGroupBox {
	w.details = qt.NewQGroupBox3("Connection details")
	l := qt.NewQVBoxLayout2()
	w.details.SetLayout(l.QLayout)
	note := qt.NewQLabel3("Send these to the people who connect. The fingerprint lets them check that they reach this computer.")
	note.SetWordWrap(true)
	l.AddWidget(note.QWidget)
	form := qt.NewQFormLayout2()
	for _, d := range detailLines {
		field := qt.NewQLineEdit2()
		field.SetReadOnly(true)
		field.SetAccessibleName(d.label)
		copyButton := qt.NewQPushButton3("Copy")
		copyButton.SetAccessibleName("Copy " + strings.ToLower(d.label[:1]) + d.label[1:])
		label := d.label
		copyButton.OnClicked(func() {
			qt.QGuiApplication_Clipboard().SetText(field.Text())
			w.setStatus(fmt.Sprintf("Copied the %s. Other programs can read what you copy.", strings.ToLower(label[:1])+label[1:]))
		})
		row := qt.NewQHBoxLayout2()
		row.AddWidget(field.QWidget)
		row.AddWidget(copyButton.QWidget)
		form.AddRow4(d.label+":", row.QLayout)
		w.fields[d.key] = field
	}
	l.AddLayout(form.QLayout)
	w.connected = qt.NewQLabel2()
	w.connected.SetWordWrap(true)
	l.AddWidget(w.connected.QWidget)
	w.details.SetVisible(false)
	return w.details
}

// Show shows the window and reads the configuration.
func (w *Window) Show() {
	w.win.Resize(720, 760)
	w.win.Show()
	w.setStatus("Reading the configuration…")
	w.run(func(ctx context.Context) func() {
		cur, err := w.app.Load(ctx)
		return func() {
			if err != nil {
				// Nothing may be written over a configuration that was
				// not read (app.Apply refuses it too).
				w.setState(broken)
				w.fail("Could not read the configuration. Fix it, then start gosftpd-gui again.", err.Error())
				return
			}
			w.loaded(cur)
			w.setState(idle)
			if len(cur.Reset) > 0 {
				w.showMore(fmt.Sprintf("The configuration gives %s settings of their own (on_conflict or create), set by hand. "+
					"Changing the folders or the port here writes the configuration again with the settings of the other folders.",
					strings.Join(cur.Reset, ", ")))
			}
			switch {
			case !cur.Configured:
				w.setStatus("Add a folder and a person, then press Start sharing.")
			case w.opts.StartSharing:
				w.startSharing()
			default:
				w.setStatus("Press Start sharing to share these folders again.")
			}
		}
	})
}

// run calls job off the main thread with a context, then the function it
// returns on the main thread.
func (w *Window) run(job func(ctx context.Context) func()) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		done := job(ctx)
		cancel()
		mainthread.Start(done)
	}()
}

// loaded shows the configuration that was read.
func (w *Window) loaded(cur app.Current) {
	w.cur = cur
	for _, r := range w.folders {
		r.w.Hide()
		r.w.DeleteLater()
	}
	w.folders = nil
	for _, f := range cur.Settings.Folders {
		w.addRow(f)
	}
	if cur.Configured {
		w.port.SetValue(cur.Port())
	}
	w.showPeople()
}

func (w *Window) showPeople() {
	if len(w.cur.People) == 0 {
		w.people.SetText("Add the person who may connect.")
		return
	}
	var names []string
	for _, p := range w.cur.People {
		how := "password"
		if !p.Password {
			how = "public key"
		}
		s := fmt.Sprintf("%s (%s)", p.Name, how)
		if p.Status == "disabled" {
			s = fmt.Sprintf("%s (%s, disabled)", p.Name, how)
		}
		names = append(names, s)
	}
	w.people.SetText("May connect: " + strings.Join(names, ", ") + ". Add someone else below, or leave the fields empty.")
}

// chooseFolder asks for a folder to share.
func (w *Window) chooseFolder() {
	home, _ := os.UserHomeDir()
	path := qt.QFileDialog_GetExistingDirectory3(w.win.QWidget, "Choose a folder to share", home)
	if path == "" {
		return
	}
	w.AddFolder(path)
}

// AddFolder adds the folder at path to the list, which people may upload
// to. Its name is none of the configuration's: a folder removed from the
// list keeps its name until sharing starts again, and the people who had
// it must not get the new folder in its place.
func (w *Window) AddFolder(path string) {
	path = filepath.Clean(path)
	names := make([]string, 0, len(w.folders)+len(w.cur.Settings.Folders))
	for _, r := range w.folders {
		if r.folder.Path == path {
			w.setStatus(fmt.Sprintf("%s is shared already, as %s.", path, r.folder.Name))
			return
		}
		names = append(names, r.folder.Name)
	}
	for _, f := range w.cur.Settings.Folders {
		if f.Path == path { // removed from the list, and added again
			w.addRow(f)
			w.setStatus(fmt.Sprintf("Added %s as %s again.", path, f.Name))
			return
		}
		names = append(names, f.Name)
	}
	f := supervisor.Folder{Name: app.FolderName(path, names), Path: path}
	w.addRow(f)
	w.setStatus(fmt.Sprintf("Added %s as %s.", path, f.Name))
}

func (w *Window) addRow(f supervisor.Folder) {
	r := &folderRow{folder: f, w: qt.NewQWidget2()}
	l := qt.NewQHBoxLayout2()
	l.SetContentsMargins(0, 0, 0, 0)
	r.w.SetLayout(l.QLayout)
	label := qt.NewQLabel3(fmt.Sprintf("%s: %s", f.Name, f.Path))
	label.SetWordWrap(true)
	l.AddWidget2(label.QWidget, 1)
	r.access = qt.NewQComboBox2()
	r.access.AddItem("People may upload")
	r.access.AddItem("Read only")
	if f.ReadOnly {
		r.access.SetCurrentIndex(accessRead)
	}
	r.access.SetAccessibleName("Access to " + f.Name)
	l.AddWidget(r.access.QWidget)
	r.remove = qt.NewQPushButton3("Remove")
	r.remove.SetAccessibleName("Remove " + f.Name)
	r.remove.OnClicked(func() { w.removeRow(r) })
	l.AddWidget(r.remove.QWidget)
	w.folderRows.AddWidget(r.w)
	w.folders = append(w.folders, r)
	w.updateEnabled()
}

func (w *Window) removeRow(r *folderRow) {
	i := slices.Index(w.folders, r)
	if i < 0 {
		return
	}
	w.folders = slices.Delete(w.folders, i, i+1)
	r.w.Hide()
	r.w.DeleteLater()
	if slices.ContainsFunc(w.cur.Settings.Folders, func(f supervisor.Folder) bool { return f.Path == r.folder.Path }) {
		w.setStatus(fmt.Sprintf("Removed %s from the list: it is no longer shared once you start sharing.", r.folder.Name))
	} else {
		w.setStatus(fmt.Sprintf("Removed %s.", r.folder.Name))
	}
	w.updateEnabled()
	w.addFolder.SetFocus()
}

// generatePassword puts a new password in the password field and shows it
// once, to copy. The dialog, and so the password in plain text, goes when
// it closes.
func (w *Window) generatePassword() {
	p := supervisor.GeneratePassword()
	w.password.SetText(p)
	w.usePassword.SetChecked(true)
	who := strings.TrimSpace(w.name.Text())
	if who == "" {
		who = "the person"
	}
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

// form is what the person filled in.
func (w *Window) form() app.Form {
	f := app.Form{Port: w.port.Value()}
	for _, r := range w.folders {
		fo := r.folder
		fo.ReadOnly = r.access.CurrentIndex() == accessRead
		f.Folders = append(f.Folders, fo)
	}
	f.Person.Name = strings.TrimSpace(w.name.Text())
	if w.usePassword.IsChecked() {
		f.Person.Password = w.password.Text()
	} else {
		f.Person.Key = strings.TrimSpace(w.key.Text())
	}
	return f
}

// startSharing writes the form to the configuration and starts gosftpd.
func (w *Window) startSharing() {
	if w.state != idle {
		return
	}
	f := w.form()
	if err := f.Check(w.cur); err != nil {
		w.fail(err.Error(), "")
		w.focusFor(f)
		return
	}
	w.setState(working)
	w.setStatus("Writing the configuration…")
	cur := w.cur
	w.run(func(ctx context.Context) func() {
		warnings, applyErr := w.app.Apply(ctx, cur, f)
		after, loadErr := w.app.Load(ctx)
		if applyErr != nil || loadErr != nil {
			return func() {
				if loadErr == nil {
					w.cur = after
					w.showPeople()
				}
				w.setState(idle)
				w.fail(firstError(applyErr, loadErr).Error(), warnings)
			}
		}
		if w.closing.Load() {
			return func() { w.setState(idle) } // quits
		}
		mainthread.Start(func() {
			w.cur = after
			w.showPeople()
			if f.Person.Name != "" {
				w.name.SetText("")
				w.password.SetText("")
				w.key.SetText("")
			}
			w.setStatus("Starting the server…")
		})
		details, err := w.app.Start(ctx, func(int) {
			mainthread.Start(func() {
				w.setStatus("The server a previous gosftpd-gui started is still stopping. Waiting for it to exit…")
			})
		})
		return func() {
			if err != nil {
				w.setState(idle)
				w.startFailed(err, warnings)
				return
			}
			w.started(details, userFor(f, after))
		}
	})
}

// userFor is the user of the connection details: the person just added,
// else the first who may log in.
func userFor(f app.Form, cur app.Current) string {
	if f.Person.Name != "" {
		return f.Person.Name
	}
	for _, p := range cur.People {
		if p.Status != "disabled" {
			return p.Name
		}
	}
	if len(cur.People) > 0 {
		return cur.People[0].Name
	}
	return ""
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// focusFor moves the focus to the field a refused form needs.
func (w *Window) focusFor(f app.Form) {
	switch {
	case len(f.Folders) == 0:
		w.addFolder.SetFocus()
	case f.Person.Name == "" && (len(w.cur.People) == 0 || f.Person.Password != "" || f.Person.Key != ""):
		w.name.SetFocus()
	case w.usePassword.IsChecked():
		w.password.SetFocus()
	default:
		w.key.SetFocus()
	}
}

func (w *Window) startFailed(err error, warnings string) {
	var se *supervisor.StartError
	var ve *supervisor.VersionError
	switch {
	case errors.As(err, &se) && se.Kind == "listen":
		w.fail(fmt.Sprintf("Could not listen on %s: %s. Another program may use port %d: choose another port.", se.Address, se.Message, w.port.Value()), joinNonEmpty(warnings, se.Stderr))
		w.port.SetFocus()
	case errors.As(err, &se):
		w.fail(se.Error(), joinNonEmpty(warnings, se.Stderr))
	case errors.As(err, &ve):
		w.fail("This gosftpd-gui and its gosftpd come from different releases: install them again from one release.", ve.Error())
	default:
		w.fail(err.Error(), warnings)
	}
}

func joinNonEmpty(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n\n")
}

// started shows the connection details of the running server, and the
// warnings it logged about its configuration. The commands' own warnings
// are shown only when one fails: those of an init that wrote a
// configuration without the person added next would mislead.
func (w *Window) started(d supervisor.Details, user string) {
	w.user = user
	w.fields["host"].SetText(d.Host)
	w.fields["port"].SetText(strconv.Itoa(d.Port))
	w.fields["user"].SetText(user)
	w.fields["fingerprint"].SetText(d.HostKeyFingerprint)
	w.fields["known_hosts"].SetText(d.KnownHosts)
	w.fields["command"].SetText(d.SFTPCommand(user))
	for _, f := range w.fields {
		f.SetCursorPosition(0)
	}
	w.who = nil
	w.connected.SetText("Nobody is connected.")
	w.setState(sharing)
	msg := fmt.Sprintf("Sharing on port %d.", d.Port)
	if len(d.Addresses) > 0 {
		msg += " This computer's addresses: " + strings.Join(d.Addresses, ", ") + "."
	}
	w.setStatus(msg)
	w.showMore(strings.Join(w.app.LogTail(), "\n"))
	w.poll.Start(500)
	done := w.app.Done()
	go func() {
		<-done
		mainthread.Start(w.exited)
	}()
	if w.quitDone {
		// The window was closed while the server started.
		w.stopSharing(false)
	}
}

// pollActivity follows who is connected.
func (w *Window) pollActivity() {
	sessions, err := w.app.Poll()
	if err != nil {
		w.showMore("Reading the audit log: " + err.Error())
		return
	}
	who := app.Names(sessions)
	if slices.Equal(who, w.who) {
		return
	}
	w.who = who
	text := "Nobody is connected."
	if len(who) > 0 {
		text = "Connected now: " + strings.Join(who, ", ") + "."
	}
	w.connected.SetText(text)
	announce(w.connected.QObject)
}

// stopSharing stops gosftpd: at once with now, else after the open
// connections end, for up to 30 s.
func (w *Window) stopSharing(now bool) {
	switch {
	case w.state == sharing:
		w.setState(stopping)
		w.app.Stop()
		if now {
			w.stopSharing(true)
			return
		}
		if len(w.who) > 0 {
			w.setStatus(fmt.Sprintf("Stopping: waiting up to 30 s for %s to disconnect. Stop now ends their connections.", strings.Join(w.who, ", ")))
		} else {
			w.setStatus("Stopping…")
		}
	case w.state == stopping && now:
		w.stopNow.SetEnabled(false)
		w.setStatus("Stopping now…")
		go w.app.StopNow()
	}
}

// exited is gosftpd's exit.
func (w *Window) exited() {
	w.poll.Stop()
	err := w.app.Exited()
	w.who = nil
	w.details.SetVisible(false)
	w.setState(idle)
	if err != nil {
		// Also on stderr: a window closed to quit is gone before anyone
		// reads it.
		fmt.Fprintln(os.Stderr, "gosftpd-gui:", err)
		summary, more, _ := strings.Cut(err.Error(), "\n")
		w.fail(summary, more)
	} else {
		w.setStatus("Sharing stopped.")
	}
}

// closeEvent stops sharing before the window closes (ADR 0013, Q3),
// asking first when someone is connected.
func (w *Window) closeEvent(super func(*qt.QCloseEvent), ev *qt.QCloseEvent) {
	if w.state == sharing && len(w.who) > 0 {
		answer := qt.QMessageBox_Question2(w.win.QWidget, "Stop sharing?",
			isAre(w.who)+" connected. Closing the window stops sharing and may cut their transfers.",
			qt.QMessageBox__Yes, qt.QMessageBox__No)
		if answer != int(qt.QMessageBox__Yes) {
			ev.Ignore()
			return
		}
		// gosftpd may have exited while the question was open: the
		// state is looked at again below.
	}
	switch w.state {
	case idle, loading, broken:
		super(ev)
		return
	case working:
		// Quit once the start has finished: the job does not start
		// gosftpd any more, or stops it if it has started already.
		w.quitDone = true
		w.closing.Store(true)
		w.setStatus("Closing…")
	case sharing:
		w.quitDone = true
		w.stopSharing(false)
	case stopping:
		w.quitDone = true
	}
	ev.Ignore()
}

func isAre(names []string) string {
	if len(names) == 1 {
		return names[0] + " is"
	}
	return strings.Join(names, ", ") + " are"
}

// setState enables what the person may do now.
func (w *Window) setState(s state) {
	w.state = s
	w.updateEnabled()
	if s == idle && w.quitDone && !w.app.Sharing() {
		mainthread.Start(qt.QCoreApplication_Quit)
	}
}

func (w *Window) updateEnabled() {
	editable := w.state == idle
	for _, r := range w.folders {
		r.access.SetEnabled(editable)
		r.remove.SetEnabled(editable)
	}
	w.noFolder.SetVisible(len(w.folders) == 0)
	w.addFolder.SetEnabled(editable)
	for _, c := range []*qt.QWidget{w.name.QWidget, w.usePassword.QWidget, w.useKey.QWidget, w.port.QWidget} {
		c.SetEnabled(editable)
	}
	pw := editable && w.usePassword.IsChecked()
	w.password.SetEnabled(pw)
	w.generate.SetEnabled(pw)
	w.key.SetEnabled(editable && !w.usePassword.IsChecked())
	w.start.SetEnabled(editable)
	w.stop.SetEnabled(w.state == sharing)
	w.stopNow.SetEnabled(w.state == sharing || w.state == stopping)
	w.details.SetVisible(w.state == sharing || w.state == stopping)
}

// setStatus shows a message in the status line and announces it.
func (w *Window) setStatus(text string) {
	w.status.SetText(text)
	announce(w.status.QObject)
}

// fail shows an error: the summary in the status line, and what gosftpd
// wrote, as it wrote it, below.
func (w *Window) fail(summary, more string) {
	w.setStatus("Error: " + summary)
	w.showMore(more)
}

func (w *Window) showMore(text string) {
	text = strings.TrimSpace(text)
	w.more.SetPlainText(text)
	w.more.SetVisible(text != "")
}

// announce tells screen readers that the text of obj changed: without an
// event, a changed label is not spoken (ADR 0013, "Look and behaviour").
func announce(obj *qt.QObject) {
	if !qt.QAccessible_IsActive() {
		return
	}
	ev := qt.NewQAccessibleEvent(obj, qt.QAccessible__NameChanged)
	defer ev.Delete()
	qt.QAccessible_UpdateAccessibility(ev)
}
