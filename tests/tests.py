# vim: ts=4 et sw=4 sts=4 :

import os
import pprint
import shutil

from base import TestBase, ConfigLocation

class TestNoErrorIfNotExisting(TestBase):

    def __init__(self):
        super().__init__("checks whether a entry for a non-existing file triggers errors")

    def run(self):
        testdir = self.createAndGetTestDir(0o770)
        testfile = os.path.sep.join((testdir, "testfile"))
        testpaths = (testdir, testfile)

        modes = {
            "easy": (0o750, 0o740),
            "secure": (0o710, 0o700),
            "paranoid": (0o700, 0o600)
        }

        entries = {}

        for profile, perms in modes.items():
            lines = entries.setdefault(profile, [])
            for path, mode in ((testdir, perms[0]), (testfile, perms[1])):
                lines.append(self.buildProfileLine(path, mode))

        self.addProfileEntries(entries)

        for profile, entries in entries.items():

            # configure the given profile as default
            self.switchSystemProfile(profile)
            res, output = self.applySystemProfile()
            if res != 0:
                self.printError("applying system profile", profile, "for non-existent file failed")



class TestCorrectMode(TestBase):

    def __init__(self):
        super().__init__("checks whether file mode assignments are correctly applied as configured")

    def run(self):
        testdir = self.createAndGetTestDir(0o770)
        testfile = os.path.sep.join((testdir, "testfile"))
        testpaths = (testdir, testfile)
        self.createTestFile(testfile, 0o444)

        modes = {
            "easy": (0o750, 0o740),
            "secure": (0o710, 0o700),
            "paranoid": (0o700, 0o600)
        }

        entries = {}

        for profile, perms in modes.items():
            lines = entries.setdefault(profile, [])
            for path, mode in ((testdir, perms[0]), (testfile, perms[1])):
                lines.append(self.buildProfileLine(path, mode))

        self.addProfileEntries(entries)

        for profile, entries in entries.items():

            for p in testpaths:
                self.printMode(p)

            # configure the given profile as default
            self.switchSystemProfile(profile)
            self.applySystemProfile()

            for path, mode in zip(testpaths, modes[profile]):
                self.assertMode(path, mode)

            print()


class TestCorrectOwner(TestBase):

    def __init__(self):
        super().__init__("checks whether file owner/group assignments are corectly applied as configured")

    def run(self):

        if self.complainOnMissingSubIdSupport():
            # we need sub-uids to test ownership changes
            return

        testdir = self.createAndGetTestDir(0o770)

        # don't use friendly user and group names but plain numerical
        # IDs instead. This way we don't have to adjust /etc/passwd
        # and /etc/group. Numerical IDs are only supported in newer
        # permctl versions.

        # we need a defined order of execution here, therefore
        # iterate over the sorted dictionary keys.
        # (in newer Python versions 3.6/3.7 dictionaries are sorted by
        # insertion order by default. Still stay backward compatible
        # for the moment.)
        #
        # we start out from 0:0 and downgrade first to 0:1 then to 1:1
        # to avoid triggering the "refusing to correct" logic in
        # permctl.
        owners = {
            "easy": (0, 0),
            "paranoid": (0, 1),
            "secure": (1, 1),
        }

        entries = {}

        for profile in sorted(owners.keys()):
            user, group = owners[profile]
            entries[profile] = [self.buildProfileLine(testdir, 0o775, owner=user, group=group)]

        self.addProfileEntries(entries)

        for profile, entries in entries.items():

            self.printMode(testdir)

            self.switchSystemProfile(profile)
            self.applySystemProfile()

            user, group = owners[profile]
            self.assertOwnership(testdir, user, group)


class TestBasePermissions(TestBase):

    def __init__(self):
        super().__init__("checks whether entries in /etc/permissions correctly apply")

    def run(self):

        testdir = self.createAndGetTestDir(0o770)
        testfile = os.path.sep.join((testdir, "testfile"))
        testpaths = (testdir, testfile)
        self.createTestFile(testfile, 0o440)

        modes = {
            testfile: 0o444,
            testdir: 0o777
        }

        lines = [self.buildProfileLine(path, mode) for path, mode in modes.items()]

        self.addProfileEntries({
            # an empty string will operate on the base permissions
            # file
            "": lines
        })

        # the mode should be the same for all profiles
        for profile in self.m_profiles:
            for p in testpaths:
                self.printMode(p)

            self.switchSystemProfile(profile)
            self.applySystemProfile()

            for path, mode in modes.items():
                self.assertMode(path, mode)
                # change the mode to something else so we can
                # check that permctl is always restoring the
                # correct mode, independent of the active
                # profile
                os.chmod(path, mode & 0o111)

        print()


class TestPackagePermissions(TestBase):

    def __init__(self):
        super().__init__("checks whether package entries in /etc/permissions.d correctly apply")

    def run(self):

        # for permissions.d the basename of a file and the
        # basename.$profile, where $profile is the currently active
        # profile, should be applied.
        testdir = self.createAndGetTestDir(0o770)
        testfile = os.path.sep.join((testdir, "testfile"))
        # this file should only be determined by the basename entry
        basefile = os.path.sep.join((testdir, "basefile"))
        testpaths = (testdir, testfile, basefile)
        self.createTestFile(testfile, 0o440)
        self.createTestFile(basefile, 0o664)
        package = "testpackage"

        modes = {
            "": (0o700, 0o400),
            "easy": (0o775, 0o664),
            "secure": (0o770, 0o660),
            "paranoid": (0o700, 0o600)
        }
        # mode for basefile
        basemode = 0o640

        entries = {}

        for profile, perms in modes.items():
            lines = entries.setdefault(profile, [])
            for path, mode in ((testdir, perms[0]), (testfile, perms[1])):
                lines.append(self.buildProfileLine(path, mode))

            if profile == "":
                lines.append(self.buildProfileLine(basefile, basemode))

        self.addPackageProfileEntries(package, entries)

        # add a duplicate per-package profile located in /etc. permctl
        # should only apply the /usr one.
        bad_entries = {
            # the basename must always exist, even if empty.
            # otherwise the more specific profiles won't be
            # processed in the first place.
            "": [],
            # only test a diverging secure package profile
            "secure": [self.buildProfileLine(basefile, 0o777)]
        }

        self.addPackageProfileEntries(package, bad_entries, ConfigLocation.ETC)

        for profile, entries in entries.items():

            for p in testpaths:
                self.printMode(p)

            # for the "empty" profile we need to choose some
            # non-existing one, otherwise permctl falls back to
            # "secure"
            self.switchSystemProfile(profile if profile else "fake")
            self.applySystemProfile()

            # for the basefile the mode should always be basemode
            # independently of the active profile
            for path, mode in zip(testpaths, modes[profile] + (basemode,)):
                self.assertMode(path, mode)

            # change mode for the basefile to check whether it's
            # actually restored independently of the active
            # profile
            os.chmod(basefile, 0o444)

            print()


class TestLocalPermissions(TestBase):

    def __init__(self):
        super().__init__("checks whether entries in *.local profiles are respected")

    def run(self):

        # entries in *.local should always take precedence over the
        # rest IIUC
        #
        # write arbitrary entries in the standard profiles, they
        # should never apply.
        #
        # then add an entry for testdir in permissions.local and one
        # in testpackage.local
        testdir = self.createAndGetTestDir(0o750)
        testfile = os.path.sep.join((testdir, "testfile"))
        testpaths = (testdir, testfile)
        self.createTestFile(testfile, 0o640)
        package = "testpackage"

        modes = {
            "": (0o770, 0o660),
            "easy": (0o775, 0o664),
            "secure": (0o710, 0o600),
            "paranoid": (0o700, 0o400),
        }

        local_perms = (0o500, 0o000)

        global_entries = {}
        pkg_entries = {}

        for profile, perms in modes.items():
            global_lines = global_entries.setdefault(profile, [])
            pkg_lines = pkg_entries.setdefault(profile, [])

            line = self.buildProfileLine(testdir, perms[0])
            global_lines.append(line)
            line = self.buildProfileLine(testfile, perms[1])
            pkg_lines.append(line)

        # this should take precendence over all other entries
        line = self.buildProfileLine(testdir, local_perms[0])
        global_entries[self.m_local_profile] = [line]
        line = self.buildProfileLine(testfile, local_perms[1])
        pkg_entries[self.m_local_profile] = [line]

        self.addProfileEntries(global_entries)
        self.addPackageProfileEntries(package, pkg_entries)

        for profile in modes.keys():

            for p in testpaths:
                self.printMode(p)

            self.switchSystemProfile(profile if profile else "fake")
            self.applySystemProfile()

            for path, mode in zip(testpaths, local_perms):
                self.assertMode(path, mode)
                # corrupt the mode to make sure it's always
                # restored later
                os.chmod(path, 0o555)

            print()


class TestDefaultProfile(TestBase):

    def __init__(self):
        super().__init__("checks whether the default profile is correctly selected")
        # if no profile is explicitly configured then this one should
        # be implicitly selected by permctl
        self.m_default_profile = "secure"

    def run(self):

        testdir = self.createAndGetTestDir(0o770)
        testfile = os.path.sep.join((testdir, "testfile"))
        testpaths = (testdir, testfile)
        self.createTestFile(testfile, 0o444)
        package = "testpackage"

        modes = {
            "": (0o700, 0o400),
            "easy": (0o775, 0o664),
            "secure": (0o770, 0o660),
            "paranoid": (0o700, 0o600)
        }

        global_entries = {}
        pkg_entries = {}

        for profile, perms in modes.items():
            global_lines = global_entries.setdefault(profile, [])
            pkg_lines = pkg_entries.setdefault(profile, [])

            line = self.buildProfileLine(testdir, perms[0])
            global_lines.append(line)
            line = self.buildProfileLine(testfile, perms[1])
            pkg_lines.append(line)

        self.addProfileEntries(global_entries)
        self.addPackageProfileEntries(package, pkg_entries)

        for path in testpaths:
            self.printMode(path)

        # write an empty profile config, this should cause the default
        # to kick in
        self.switchSystemProfile("")
        self.applySystemProfile()

        for path, mode in zip(testpaths, modes[self.m_default_profile]):
            self.assertMode(path, mode)

        print()


class TestCommandLineBase(TestBase):
    """A base class for a couple or simpler command line switch tests.
    setupTest() provides a common profile setup for use by
    specializations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setupTest(self):

        testdir_root = self.createAndGetTestDir(0o755)
        testdir_a = os.path.join(testdir_root, "sub1")
        testfile_a = os.path.join(testdir_a, "file1")
        testdir_b = os.path.join(testdir_root, "sub2")
        testfile_b = os.path.join(testdir_b, "file2")
        for d in (testdir_a, testdir_b):
            os.mkdir(d, 0o755)
        for f in (testfile_a, testfile_b):
            self.createTestFile(f, 0o444)
        package = "testpackage"

        global_testpaths = (testdir_a, testfile_a)
        pkg_testpaths = (testdir_b, testfile_b)

        modes = {
            "": (0o700, 0o400),
            "easy": (0o755, 0o664),
            "secure": (0o770, 0o660),
            "paranoid": (0o700, 0o600)
        }

        entries = {}

        for profile, perms in modes.items():
            lines = entries.setdefault(profile, [])
            for path, mode in zip(global_testpaths, modes[profile]):
                lines.append(self.buildProfileLine(path, mode))

        self.addProfileEntries(entries)

        entries = {}

        for profile, perms in modes.items():
            lines = entries.setdefault(profile, [])
            for path, mode in zip(pkg_testpaths, modes[profile]):
                lines.append(self.buildProfileLine(path, mode))

        self.addPackageProfileEntries(package, entries)

        self.m_global_testpaths = global_testpaths
        self.m_pkg_testpaths = pkg_testpaths
        self.m_testpaths = self.m_global_testpaths + self.m_pkg_testpaths
        self.m_modes = modes
        self.m_testdir_root = testdir_root


class TestForceProfile(TestCommandLineBase):

    def __init__(self):

        super().__init__("Tests whether the `--level` override works")

    def run(self):

        self.setupTest()

        forced_level = "paranoid"
        expected_modes = self.m_modes[forced_level] * 2

        for profile in self.m_profiles:
            # independently of the configured system profile, the
            # forced level should always be applied
            self.switchSystemProfile(profile)
            self.applySystemProfile(["--level", forced_level])

            for path, mode in zip(self.m_testpaths, expected_modes):
                self.assertMode(path, mode)


class TestWarnMode(TestCommandLineBase):

    def __init__(self):

        super().__init__("Tests whether the `--warn` switch works as expected")

    def run(self):
        self.setupTest()

        init_profile = "easy"
        expected_modes = self.m_modes[init_profile] * 2
        self.switchSystemProfile(init_profile)
        self.applySystemProfile()

        for profile in self.m_profiles:
            self.switchSystemProfile(profile)
            self.applySystemProfile(["--warn"])

            for path, mode in zip(self.m_testpaths, expected_modes):
                # modes should never change after the initial switch
                self.assertMode(path, mode)


class TestExamineSwitch(TestCommandLineBase):

    def __init__(self):

        super().__init__("Tests whether the `--examine` switch works as expected")

    def run(self):
        self.setupTest()

        # first get a defined state
        init_profile = "easy"
        self.switchSystemProfile(init_profile)
        self.applySystemProfile()
        expected_modes = self.m_modes[init_profile] * 2

        # choose an arbitrary config item for the test
        examine_index = 0  # 0 is for the dir, 1 is for the file mode
        examine_path = self.m_testpaths[2]

        for profile in self.m_profiles:
            self.switchSystemProfile(profile)
            self.applySystemProfile(["--examine", examine_path])

            # only examine_path should now be changed, all else
            # should stay at "easy" level
            for path, mode in zip(self.m_testpaths, expected_modes):
                if path != examine_path:
                    self.assertMode(path, mode)
                else:
                    # the --examine path should be
                    # switched to the according profile
                    self.assertMode(path, self.m_modes[profile][examine_index])


class TestRootSwitch(TestCommandLineBase):

    def __init__(self):

        super().__init__("Tests whether the `--root` switch works as expected")

    def run(self):
        self.setupTest()
        caps_file = self.m_testdir_root + "/caps_test"
        caps_profile = "easy"
        caps = ["cap_net_admin=ep"]
        self.createTestFile(caps_file, 0o755)

        init_profile = "easy"
        self.addProfileEntries({
            caps_profile: [self.buildProfileLine(caps_file, 0o750, caps=caps)]
        })
        self.switchSystemProfile(init_profile)
        self.applySystemProfile()
        expected_modes = self.m_modes[init_profile] * 2

        # now only operate on the alternative root directory
        alt_root = "/altroot"
        os.mkdir(alt_root)
        # copy over our configured entries to the alt root
        shutil.copytree(self.m_testdir_root, alt_root + self.m_testdir_root)

        alt_testpaths = [alt_root + path for path in self.m_testpaths]

        for profile in self.m_profiles:
            self.switchSystemProfile(profile)
            self.applySystemProfile(["--root", alt_root])

            # the original root should be unaltered
            for path, mode in zip(self.m_testpaths, expected_modes):
                self.assertMode(path, mode)

            # the alternative root should be accordingly adjusted
            for path, mode in zip(alt_testpaths, self.m_modes[profile] * 2):
                self.assertMode(path, mode)

            if profile == caps_profile:
                self.assertHasCaps(alt_root + caps_file, caps)

            print()


class TestFilesSwitch(TestCommandLineBase):

    def __init__(self):

        super().__init__("Tests whether the `--files` switch works as expected")

    def run(self):
        self.setupTest()

        # this switch actually just reads a list of --examine paths
        # from a file.

        # get a defined start state
        init_profile = "easy"
        self.switchSystemProfile(init_profile)
        self.applySystemProfile()

        # write a custom profile file only affected one of the paths
        # present in the other profiles
        testpath = self.m_testpaths[0]
        mode_index = 0
        files_path = "/tmp/files.list"
        with open(files_path, 'w') as files_file:
            files_file.write(testpath + "\n")

        for profile in self.m_profiles:
            self.switchSystemProfile(profile)
            self.applySystemProfile(["--files", files_path])

            # modes should always be the same: easy profiles for
            # everything but the testpath, which should be at
            # the mode for the current profile
            for path, mode in zip(self.m_testpaths, self.m_modes[init_profile] * 2):
                if path != testpath:
                    self.assertMode(path, mode)
                else:
                    self.assertMode(path, self.m_modes[profile][mode_index])

            print()


class TestCapabilities(TestBase):

    def __init__(self):

        super().__init__("checks whether capability settings and related command line options work")

    def run(self):

        if not self.m_main_test_instance.haveCapSupport():
            self.printWarning("Cannot set file capabilities in user namespaces on this kernel. It only works starting from version 4.14")
            return

        testfile = "/caps_test"
        self.createTestFile(testfile, 0o755)

        # just test a single profile in this case, we just want to see
        # whether caps work at all
        profile = "easy"
        mode = 0o750
        caps = ["cap_net_admin", "cap_net_raw=ep"]

        entries = {
            profile: [self.buildProfileLine(testfile, mode, caps=caps)]
        }

        self.addProfileEntries(entries)

        self.switchSystemProfile(profile)
        # by default caps should be set, if in the sysconfig
        # configuration not value is set (but the variable still needs
        # to be there).
        self.applySystemProfile()

        self.assertHasCaps(testfile, caps)

        os.unlink(testfile)
        self.createTestFile(testfile, 0o755)
        self.applySystemProfile(["--no-fscaps"])

        # this time there should be no extended attribute at all
        self.assertNoCaps(testfile)


class TestACLs(TestBase):

    def __init__(self):

        super().__init__("checks whether managment of ACLs works as expected")

    def run(self):

        file_missing_acl = "/missing_acl"
        file_mismatch_acl = "/mismatch_acl"
        # gets assigned an ACL but is not configured for an ACL -> ACL should
        # be dropped by permctl
        file_extra_acl = "/extra_acl"
        # a basic ACL is configured for this file, which should be rejected
        file_basic_acl = "/basic_acl"
        # configuration of multiple ACL entries and capabilities, all should apply correctly
        file_acl_and_cap = "/acl_plus_cap"

        self.createTestFile(file_missing_acl, 0o755)
        self.createTestFile(file_mismatch_acl, 0o755)
        self.addACLEntries(file_mismatch_acl, "user:bin:r-x")
        self.createTestFile(file_extra_acl, 0o755)
        self.addACLEntries(file_extra_acl, "user:nobody:rwx")
        self.createTestFile(file_basic_acl, 0o444)
        self.createTestFile(file_acl_and_cap, 0o111)

        # just test a single profile, we just want to see whether ACLs work at all
        profile = "easy"

        entries = {
                profile: [
                    self.buildProfileLine(file_missing_acl, 0o444, acl="user:nobody:rwx"),
                    self.buildProfileLine(file_mismatch_acl, 0o444, acl="user:nobody:rwx"),
                    self.buildProfileLine(file_extra_acl, 0o444),
                    self.buildProfileLine(file_basic_acl, 0o755, acl="user::rw-,group::rw-,other::rw-"),
                    self.buildProfileLine(file_acl_and_cap, 0o444,
                                          acl=["user:nobody:rw-", "user:bin:--x"],
                                          caps=["cap_net_admin=ep"])
                ]
        }

        self.addProfileEntries(entries)

        self.switchSystemProfile(profile)
        _, permctl_lines = self.applySystemProfile()

        # we are expecting the group mode to reflect the ACL mask now, which is
        # 'rwx' due to the user:nobody ACL entry.
        self.checkACL(file_missing_acl, "missing_acl", "user:nobody:rwx", 0o474)
        self.checkACL(file_mismatch_acl, "mismatch_acl", "user:nobody:rwx", 0o474)
        self.checkACL(file_extra_acl, "extra_acl", [], 0o444)

        self.checkACL(file_basic_acl, "basic_acl", [], 0o755)
        for line in permctl_lines:
            if line.find("does not contain extended privileges") != -1:
                print("basic ACL config was properly rejected by permctl")
                break
        else:
            self.printError("basic_acl config was not rejected / diagnosed?")

        self.checkACL(file_acl_and_cap, "acl_plus_cap", ["user:nobody:rw-", "user:bin:--x"], 0o474)
        self.assertHasCaps(file_acl_and_cap, ["cap_net_admin=ep"])

    def checkACL(self, path, label, entries, mode):
        if not isinstance(entries, list):
            entries = [entries]
        actual_entries = self.getACLEntries(path)

        entries.sort()
        actual_entries.sort()

        if entries == actual_entries:
            print(label, ": ACL entries (if any) are as expected", sep='')
        else:
            self.printError(label, ": ACL entries are not as expected", sep='')
            self.printACL(actual_entries)

        if self.getMode(path) != mode:
            self.printError(label, ": basic mode of file is unexpected", sep='')


    def printACL(self, entries):
        print("found", len(entries), "entries:")
        for entry in entries:
            print("-", entry)


class TestUnexpectedPathOwner(TestBase):

    def __init__(self):

        super().__init__("checks whether changes are rejected when parent dir owner and target path owner don't match")

    def run(self):

        if self.complainOnMissingSubIdSupport():
            return

        testdir = self.createAndGetTestDir(0o755)
        baddir = os.path.join(testdir, "dir")
        badfile = os.path.join(testdir, "file")

        self.createTestFile(badfile, 0o644)
        self.createTestDir(baddir, 0o755)

        testprofile = "easy"

        entries = {
            testprofile: (
                # add a trailing slash to express that we want
                # a directory here
                self.buildProfileLine(baddir + "/", 0o500),
                self.buildProfileLine(badfile, 0o600)
            )
        }

        self.addProfileEntries(entries)
        os.chown(badfile, 1, 1, follow_symlinks=False)
        os.chown(baddir, 1, 1, follow_symlinks=False)
        orig_file_mode = self.getMode(badfile)
        orig_dir_mode = self.getMode(baddir)

        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()
        # make sure modes actually didn't change
        # before bind mounts are removed
        self.assertMode(badfile, orig_file_mode)
        self.assertMode(baddir, orig_dir_mode)

        found_dir_reject = False
        found_file_reject = False

        # we can't evaluate the exit code in this case, even if the
        # modes aren't corrected permctl returns 0.
        #
        # instead parse permctl's output to determine it correctly
        # refused to do anything
        messages = self.extractMessagesFromPermctl(lines, [baddir, badfile])
        needle = "unexpected owner"

        for message in messages[baddir]:
            if message.find(needle) != -1:
                found_dir_reject = True
                break
        for message in messages[badfile]:
            if message.find(needle) != -1:
                found_file_reject = True
                break

        print(baddir, "rejected =", found_dir_reject)
        print(badfile, "rejected =", found_file_reject)

        if found_dir_reject and found_file_reject:
            # all fine
            return

        self.printError("bad directory and/or bad file were not rejected")


class TestUnexpectedPathGroup(TestBase):

    def __init__(self):

        super().__init__("checks whether changes are rejected when a group controlled path is involved")

    def run(self):

        if self.complainOnMissingSubIdSupport():
            return

        testdir = self.createAndGetTestDir(0o755)
        baddir = os.path.join(testdir, "dir")
        badfile = os.path.join(testdir, "file")

        self.createTestFile(badfile, 0o664)
        self.createTestDir(baddir, 0o775)

        testprofile = "easy"

        entries = {
            testprofile: (
                # add a trailing slash to express that we want
                # a directory here
                self.buildProfileLine(baddir + "/", 0o500),
                self.buildProfileLine(badfile, 0o600)
            )
        }

        self.addProfileEntries(entries)
        os.chown(badfile, 0, 1, follow_symlinks=False)
        os.chown(baddir, 0, 1, follow_symlinks=False)
        orig_file_mode = self.getMode(badfile)
        orig_dir_mode = self.getMode(baddir)

        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()
        # make sure modes actually didn't change
        # before bind mounts are removed
        self.assertMode(badfile, orig_file_mode)
        self.assertMode(baddir, orig_dir_mode)

        found_dir_reject = False
        found_file_reject = False

        # we can't evaluate the exit code in this case, even if the
        # modes aren't corrected permctl returns 0.
        #
        # instead parse permctl's output to determine it correctly
        # refused to do anything
        messages = self.extractMessagesFromPermctl(lines, [baddir, badfile])
        needle = "unexpected group"

        for message in messages[baddir]:
            if message.find(needle) != -1:
                found_dir_reject = True
                break
        for message in messages[badfile]:
            if message.find(needle) != -1:
                found_file_reject = True
                break

        print(baddir, "rejected =", found_dir_reject)
        print(badfile, "rejected =", found_file_reject)

        if found_dir_reject and found_file_reject:
            # all fine
            return

        self.printError("bad directory and/or bad file were not rejected")


class TestRejectWorldWritable(TestBase):

    def __init__(self):

        super().__init__("checks that world-writable target files aren't touched")

    def run(self):

        testdir = self.createAndGetTestDir(0o755)
        badfile = os.path.join(testdir, "file")

        self.createTestFile(badfile, 0o666)

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(badfile, 0o640),
            )
        }

        self.addProfileEntries(entries)

        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()

        # like in the other cases, don't check the exit code, rely on
        # output parsing
        messages = self.extractMessagesFromPermctl(lines, badfile)
        needle = "world-writable"
        found_rejection = False

        for message in messages[badfile]:
            if message.find(needle) != -1:
                print("found rejection message")
                found_rejection = True
                break

        if not found_rejection:
            self.printError("world-writable file", badfile, "was not rejected")
            return

        self.assertMode(badfile, 0o666)


class TestRejectInsecurePath(TestBase):

    def __init__(self):
        super().__init__("checks whether paths with insecure inter-mediate ownership are rejected")

    def run(self):

        if self.complainOnMissingSubIdSupport():
            return

        testroot = self.createAndGetTestDir(0o755)
        testpath = os.path.join(testroot, "badowner")
        self.createTestDir(testpath, 0o755)
        os.chown(testpath, 1, 0)
        testpath = os.path.join(testpath, "middle2")
        self.createTestDir(testpath, 0o755)
        testpath = os.path.join(testpath, "somefile")
        self.createTestFile(testpath, 0o644)
        somefile1 = testpath

        testpath = os.path.join(testroot, "badgroup")
        self.createTestDir(testpath, 0o775)
        os.chown(testpath, 0, 1)
        testpath = os.path.join(testpath, "middle2")
        self.createTestDir(testpath, 0o755)
        testpath = os.path.join(testpath, "somefile")
        self.createTestFile(testpath, 0o644)
        somefile2 = testpath

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(somefile1, 0o400),
                self.buildProfileLine(somefile2, 0o400),
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()
        # make sure the mode really didn't change
        self.assertMode(somefile1, 0o644)
        self.assertMode(somefile2, 0o644)

        messages = self.extractMessagesFromPermctl(lines, [somefile1, somefile2])
        needle = "on an insecure path"

        for insecure in (somefile1, somefile2):
            found_rejection = False

            for message in messages[insecure]:
                if message.find(needle) != -1:
                    found_rejection = True
                    print("found rejection message for", insecure)
                    break

            if not found_rejection:
                self.printError("insecure path", insecure, "was not rejected")
                return


class TestUnknownOwnership(TestBase):

    def __init__(self):

        super().__init__("checks whether config entries for unknown user/group are rejected")

    def run(self):

        testroot = self.createAndGetTestDir(0o755)
        username = "bad_user"
        groupname = "bad_group"
        baduser_file = os.path.join(testroot, username)
        badgroup_file = os.path.join(testroot, groupname)
        self.createTestFile(baduser_file, 0o400)
        self.createTestFile(badgroup_file, 0o400)

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(baduser_file, 0o500, owner=username),
                self.buildProfileLine(badgroup_file, 0o600, group=groupname)
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile(["--verbose"])

        messages = self.extractMessagesFromPermctl(lines, (baduser_file, badgroup_file))

        found_baduser_report = False
        baduser_needle = "unknown user {}".format(username)

        for message in messages[baduser_file]:
            if message.find(baduser_needle) != -1:
                found_baduser_report = True
                break

        found_badgroup_report = False
        badgroup_needle = "unknown group {}".format(groupname)

        for message in messages[badgroup_file]:
            if message.find(badgroup_needle) != -1:
                found_badgroup_report = True
                break

        print(baduser_file, "rejected =", found_baduser_report)
        print(badgroup_file, "rejected =", found_badgroup_report)

        if not found_baduser_report or not found_badgroup_report:
            self.printError("bad user and/or group were not rejected")
            return

        # make sure the mode really didn't change
        self.assertMode(baduser_file, 0o400)
        self.assertMode(badgroup_file, 0o400)


class TestRejectUserSymlink(TestBase):

    def __init__(self):

        super().__init__("checks whether user-owned symlinks in early path components are rejected")

    def run(self):

        if self.complainOnMissingSubIdSupport():
            return

        testroot = self.createAndGetTestDir(0o755)

        testlink = os.path.join(testroot, "link")
        os.symlink("subdir", testlink)
        os.chown(testlink, 1, 1, follow_symlinks=False)

        subdir = os.path.join(testroot, "subdir")
        self.createTestDir(subdir, 0o755)

        testfile = os.path.join(testlink, "testfile")
        self.createTestFile(testfile, 0o700)

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(testfile, 0o744),
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()

        messages = self.extractMessagesFromPermctl(lines, testlink)
        needle = "on an insecure path"

        found_badlink_report = False

        for message in messages[testlink]:
            if message.find(needle) != -1:
                found_badlink_report = True
                break

        print(testlink, "rejected =", found_badlink_report)

        if not found_badlink_report:
            self.printError("user owned symlink in path was not rejected")

        # make sure that the mode actually didn't change
        self.assertMode(testfile, 0o700)


class TestPrivsForSpecialFiles(TestBase):

    def __init__(self):

        super().__init__("checks that set*id bits and caps aren't assigned to special files")

    def run(self):

        testroot = self.createAndGetTestDir(0o755)
        specials = []
        for _type in ("uid", "gid", "caps"):
            testspecial = os.path.join(testroot, "special." + _type)
            os.mkfifo(testspecial)
            orig_mode = self.getMode(testspecial)
            specials.append((testspecial, orig_mode))

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(specials[0][0], 0o4755),
                self.buildProfileLine(specials[1][0], 0o2755),
                self.buildProfileLine(specials[2][0], 0o0644, caps=["cap_net_admin=ep"])
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()

        messages = self.extractMessagesFromPermctl(lines, [s[0] for s in specials])
        needle = "will only assign capabilities"
        found_rejects = 0

        for path, _ in specials:
            for message in messages[path]:
                if message.find(needle) != -1:
                    found_rejects += 1
                    break

        print("Rejects found:", found_rejects)

        if found_rejects != len(specials):
            self.printError("setuid/setgid/caps for FIFO were not rejected")
            return

        for path, mode in specials:
            self.assertMode(path, mode)

        self.assertNoCaps(specials[2][0])


class TestPrivsOnInsecurePath(TestBase):

    def __init__(self):

        super().__init__("checks that no privileges are set beneath path owned by different users")

    def run(self):

        # create a world-writable testroot, which is the insecure part
        # in this test
        testroot = self.createAndGetTestDir(0o777)
        targetdir = os.path.join(testroot, "subdir")
        orig_file_mode = 0o755
        targetfiles = []
        for _type in ("uid", "gid", "caps"):
            targetfile = os.path.join(targetdir, "testfile." + _type)
            targetfiles.append(targetfile)

        self.createTestDir(targetdir, 0o755)
        for path in targetfiles:
            self.createTestFile(path, orig_file_mode)

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(targetfiles[0], 0o4755),
                self.buildProfileLine(targetfiles[1], 0o2755),
                self.buildProfileLine(targetfiles[2], 0o700, caps=["cap_net_admin=ep"])
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        code, lines = self.applySystemProfile()

        for path in targetfiles:
            self.assertMode(path, orig_file_mode)

        self.assertNoCaps(targetfiles[2])

        messages = self.extractMessagesFromPermctl(lines, targetfiles)
        needle = "will not give away capabilities"
        found_rejects = 0

        for path in targetfiles:
            for message in messages[path]:
                if message.find(needle) != -1:
                    found_rejects += 1
                    break

        print("Rejects found:", found_rejects)

        if found_rejects != len(targetfiles):
            self.printError("setuid/setgid/caps on insecure path were not rejected")


class TestSymlinkBehaviour(TestBase):

    def __init__(self):

        super().__init__("checks that final symlink components in paths are handled correctly")

    def run(self):

        # this test is about what happens when the final path
        # component is a valid, secure symlink.
        #
        # two cases are considered:
        # - an absolute symlink
        # - a relative symlink
        #
        # behaviour should be the same for both.
        #
        # in older permctl versions symlinks have not been followed,
        # in newer ones they were followed in a safe manner, but
        # in-between an inconsistency was present between absolute and
        # relative symlinks.
        # Current versions revert to the legacy behaviour of only following
        # dir symlinks but not links in the final path element.
        testroot = self.createAndGetTestDir(0o755)

        testfile1 = os.path.join(testroot, "file1")
        testfile2 = os.path.join(testroot, "file2")

        self.createTestFile(testfile1, 0o600)
        self.createTestFile(testfile2, 0o600)

        testlink1 = os.path.join(testroot, "link1")
        testlink2 = os.path.join(testroot, "link2")
        testlink3 = os.path.join(testroot, "link3")

        # absolute symlink
        os.symlink(testfile1, testlink1)
        # relative symlink
        os.symlink(".." + testfile2, testlink2)
        # a very short relative symlink, middle component of testfile3
        # this can catch certain classes of processing errors in
        # safeOpen()
        os.symlink("d", testlink3)
        # the directory testlink3 is pointing to
        self.createTestDir(os.path.join(testroot, "d"), 0o755)

        testfile3 = os.path.join(testlink3, "file3")
        self.createTestFile(testfile3, 0o644)

        testprofile = "easy"

        entries = {
            testprofile: (
                self.buildProfileLine(testlink1, 0o644),
                self.buildProfileLine(testlink2, 0o644),
                self.buildProfileLine(testfile3, 0o600),
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        self.applySystemProfile()

        if self.assertMode(testlink1, 0o600) and self.assertMode(testlink2, 0o600):
            print("Modes of symlink targets have been ignored correctly")

        if self.assertMode(testfile3, 0o600):
            print("Mode of regular file target with short symlink component was set correctly")


class TestSymlinkDirBehaviour(TestBase):

    def __init__(self):

        super().__init__("checks that intermediary trusted symlink components in paths are handled correctly")

    def run(self):

        # this test is about what happens when a directory
        # is a valid, secure symlink. It should always be followed.
        #
        # two cases are considered:
        # - an absolute symlink
        # - a relative symlink
        #
        # behaviour should be the same for both.
        #
        # symlink handling is difficult:
        #  - for relative links permctl needs to keep proper track of the parent directory
        #  - for absolute links, the configured root may not be escaped

        testroot = self.createAndGetTestDir(0o755)

        testfile1 = os.path.join(testroot, "file1")
        testfile2 = os.path.join(testroot, "file2")

        self.createTestFile(testfile1, 0o600)
        self.createTestFile(testfile2, 0o600)

        testlink1 = os.path.join(testroot, self.getName() + "_rel_link")
        testlink2 = os.path.join(testroot, self.getName() + "_abs_link")

        # absolute symlink
        os.symlink("../../../../../" + testroot, testlink1)
        # relative symlink
        os.symlink("/../../../../../" + testroot, testlink2)

        testprofile = "easy"

        # the configured paths, where a dir is a link
        testpath1 = os.path.join(testlink1, "file1")
        testpath2 = os.path.join(testlink2, "file2")

        entries = {
            testprofile: (
                self.buildProfileLine(testpath1, 0o644),
                self.buildProfileLine(testpath2, 0o644),
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        self.applySystemProfile()

        if self.assertMode(testfile1, 0o644) and self.assertMode(testfile2, 0o644):
            print("Modes of symlink targets have been adjusted correctly")


class TestVariablesBase(TestBase):

    def createVariablesConf(self, var_map):
        """Creates a variables.conf file from the given dictionary.

        Expects a dictionary like

        {"myvar": ["/path/1", "/path/2"]}.
        """
        with open(self.getVariablesConfPath(), 'w') as varconf_fd:

            for var, values in var_map.items():
                varconf_fd.write("{} = {}\n".format(
                    var, ' '.join(values)
                ))


class TestVariableParsing(TestVariablesBase):

    def __init__(self):

        super().__init__("tests parsing of variables.conf")

    def run(self):
        variables = {
            "var1": ["file1", "file2"],
            "var2": ["sub/dir1", "sub/dir2"]
        }

        print("Creating variables.conf from:")
        pprint.pprint(variables)
        print()

        self.createVariablesConf(variables)

        res, lines = self.callPermctl(["--print-variables"])
        print()

        if res != 0:
            self.printError("failed to run permctl to print parsed variables")
            return

        parsed = {}
        cur_var = ""

        for line in lines:

            line = line.strip()

            if not line.startswith("- "):
                var = line.strip(':')
                parsed[var] = []
                cur_var = var
            else:
                parts = line.split()
                if len(parts) != 2:
                    continue

                parsed[cur_var].append(parts[1])

        if parsed == variables:
            print("parsed variables match expected values")
        else:
            self.printError("printed variables don't match expected variables")


class TestVariableApplication(TestVariablesBase):

    def __init__(self):

        super().__init__("tests application of variables in permissions lines")

    def run(self):

        testroot = self.createAndGetTestDir(0o755)

        for d in ("dir1", "dir2"):
            dpath = os.path.join(testroot, d)
            self.createTestDir(dpath, 0o755)
            for f in ("file1", "file2"):
                fpath = os.path.join(dpath, f)
                self.createTestFile(fpath, 0o600)

        variables = {
            "vardir": ["dir1", "dir2"],
            "varfile": ["file1", "file2"]
        }

        self.createVariablesConf(variables)

        testprofile = "easy"
        testpath = testroot + "/%{vardir}/%{varfile}"
        print(testpath)

        entries = {
            testprofile: (
                self.buildProfileLine(testpath, 0o644),
            )
        }

        self.addProfileEntries(entries)
        self.switchSystemProfile(testprofile)
        self.applySystemProfile()

        for d in ("dir1", "dir2"):
            dpath = os.path.join(testroot, d)
            for f in ("file1", "file2"):
                fpath = os.path.join(dpath, f)
                if self.assertMode(fpath, 0o644):
                    print("Mode of", fpath, "has been adjusted correctly")


tests = (
    TestNoErrorIfNotExisting,
    TestCorrectMode,
    TestCorrectOwner,
    TestBasePermissions,
    TestPackagePermissions,
    TestLocalPermissions,
    TestDefaultProfile,
    TestForceProfile,
    TestWarnMode,
    TestExamineSwitch,
    TestRootSwitch,
    TestFilesSwitch,
    TestCapabilities,
    TestUnexpectedPathOwner,
    TestUnexpectedPathGroup,
    TestRejectWorldWritable,
    TestRejectInsecurePath,
    TestUnknownOwnership,
    TestRejectUserSymlink,
    TestPrivsForSpecialFiles,
    TestPrivsOnInsecurePath,
    TestSymlinkBehaviour,
    TestSymlinkDirBehaviour,
    TestVariableParsing,
    TestVariableApplication,
    TestACLs
)
