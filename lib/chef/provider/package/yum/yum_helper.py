#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import sys
import yum
import signal
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'simplejson'))
try:
    import json
except ImportError:
    import simplejson as json
import re
from rpmUtils.miscutils import stringToVersion,compareEVR
from rpmUtils.arch import getBaseArch, getArchList

from yum.misc import string_to_prco_tuple

# hack to work around https://github.com/chef/chef/issues/7126
# see https://bugzilla.redhat.com/show_bug.cgi?id=1396248
if not hasattr(yum.packages.FakeRepository, 'compare_providers_priority'):
    yum.packages.FakeRepository.compare_providers_priority = 99


class MyYumBase(object):
    base = None

    def __enter__(self):
        self.base = yum.YumBase()
        return self.base

    def __exit__(self, *args, **kwargs):
        if self.base is not None:
            return self.base.closeRpmDB()
        self.base = None


class YumWrapper(object):
    base = None
    inpipe = None
    outpipe = None

    def __init__(self, base):
        self.base = base
        signal.signal(signal.SIGINT, self.exit_handler)
        signal.signal(signal.SIGHUP, self.exit_handler)
        signal.signal(signal.SIGPIPE, self.exit_handler)
        signal.signal(signal.SIGQUIT, self.exit_handler)

        if len(sys.argv) < 3:
            self.inpipe = sys.stdin
            self.outpipe = sys.stdout
        else:
            self.inpipe = os.fdopen(int(sys.argv[1]), "r")
            self.outpipe = os.fdopen(int(sys.argv[2]), "w")

    # the design of this helper is that it should try to be 'brittle' and fail hard and exit in order
    # to keep process tables clean.  additional error handling should probably be added to the retry loop
    # on the ruby side.
    def exit_handler(self, signal, frame):
        if self.base is not None:
            self.base.closeRpmDB()
        sys.exit(0)

    def versioncompare(self, versions):
        arch_list = getArchList()
        candidate_arch1 = versions[0].split(".")[-1]
        candidate_arch2 = versions[1].split(".")[-1]

        # The first version number passed to this method is always a valid nevra (the current version)
        # If the second version number looks like it does not contain a valid arch
        # then we'll chop the arch component (assuming it *is* a valid one) from the first version string
        # so we're only comparing the evr portions.
        if (candidate_arch2 not in arch_list) and (candidate_arch1 in arch_list):
            final_version1 = versions[0].replace("." + candidate_arch1,"")
        else:
            final_version1 = versions[0]

        final_version2 = versions[1]

        (e1, v1, r1) = stringToVersion(final_version1)
        (e2, v2, r2) = stringToVersion(final_version2)

        evr_comparison = compareEVR((e1, v1, r1), (e2, v2, r2))
        self.outpipe.write("%(e)s\n".format({'e': evr_comparison}))
        self.outpipe.flush()

    def install_only_packages(self, name):
        name_in_installonlypkgs = False
        name_in_installonlypkgs = name in self.base.conf.installonlypkgs
        if name_in_installonlypkgs:
            self.outpipe.write('True')
        else:
            self.outpipe.write('False')
        self.outpipe.flush()

    def query(self, command):
        enabled_repos = self.base.repos.listEnabled()

        # Handle any repocontrols passed in with our options

        if 'repos' in command:
            for repo in command['repos']:
                if 'enable' in repo:
                    self.base.repos.enableRepo(repo['enable'])
                if 'disable' in repo:
                    self.base.repos.disableRepo(repo['disable'])

        args = {'name': command['provides']}
        do_nevra = False
        if 'epoch' in command:
            args['epoch'] = command['epoch']
            do_nevra = True
        if 'version' in command:
            args['ver'] = command['version']
            do_nevra = True
        if 'release' in command:
            args['rel'] = command['release']
            do_nevra = True
        if 'arch' in command:
            desired_arch = command['arch']
            args['arch'] = command['arch']
            do_nevra = True
        else:
            desired_arch = getBaseArch()

        obj = None
        if command['action'] == "whatinstalled":
            obj = self.base.rpmdb
        else:
            obj = self.base.pkgSack

        # if we are given "name == 1.2.3" then we must use the getProvides() API.
        #   - this means that we ignore arch and version properties when given prco tuples as a package_name
        #   - in order to fix this, something would have to happen where getProvides was called first and
        #     then the result was searchNevra'd.  please be extremely careful if attempting to fix that
        #     since searchNevra does not support prco tuples.
        if bool(re.search('\\s+', command['provides'])):
            # handles flags (<, >, =, etc) and versions, but no wildcareds
            # raises error for any invalid input like: 'FOO BAR BAZ' 
            pkgs = obj.getProvides(*string_to_prco_tuple(command['provides']))
        elif do_nevra:
            # now if we're given version or arch properties explicitly, then we do a SearchNevra.
            #  - this means that wildcard version in the package_name with an arch property will not work correctly
            #  - again don't try to fix this just by pushing bugs around in the code, you would need to call
            #    returnPackages and searchProvides and then apply the Nevra filters to those results.
            pkgs = obj.searchNevra(**args)
            if (command['action'] == "whatinstalled") and (not pkgs):
                pkgs = obj.searchNevra(name=args['name'], arch=desired_arch)
        else:
            pats = [command['provides']]
            pkgs = obj.returnPackages(patterns=pats)

            if not pkgs:
                # handles wildcards
                pkgs = obj.searchProvides(command['provides'])

        if not pkgs:
            self.outpipe.write(command['provides'].split().pop(0)+' nil nil\n')
            self.outpipe.flush()
        else:
            # make sure we picked the package with the highest version
            pkgs = self.base.bestPackagesFromList(pkgs, single_name=True)
            pkg = pkgs.pop(0)
            self.outpipe.write("%(n)s %(e)s:%(v)s-%(r)s %(a)s\n" % { 'n': pkg.name, 'e': pkg.epoch, 'v': pkg.version, 'r': pkg.release, 'a': pkg.arch })
            self.outpipe.flush()

        # Reset any repos we were passed in enablerepo/disablerepo to the original state in enabled_repos
        if 'repos' in command:
            for repo in command['repos']:
                if 'enable' in repo:
                    if self.base.repos.getRepo(repo['enable']) not in enabled_repos:
                        self.base.repos.disableRepo(repo['enable'])
                if 'disable' in repo:
                    if self.base.repos.getRepo(repo['disable']) in enabled_repos:
                        self.base.repos.enableRepo(repo['disable'])


    def yum_input_loop(self):
        while 1:
            # stop the process if the parent proc goes away
            ppid = os.getppid()
            if ppid == 1:
                raise RuntimeError("orphaned")

            line = self.inpipe.readline()

            # only way to detect EOF in python
            if line == "":
                break

            try:
                command = json.loads(line)
            except ValueError:
                raise RuntimeError("bad json parse")

            if command['action'] == "whatinstalled":
                self.query(command)
            elif command['action'] == "whatavailable":
                self.query(command)
            elif command['action'] == "versioncompare":
                self.versioncompare(command['versions'])
            elif command['action'] == "installonlypkgs":
                self.install_only_packages(command['package'])
            else:
                raise RuntimeError("bad command")


if __name__ == '__main__':
    with MyYumBase() as base:
        yum_wrapper = YumWrapper(base)
        yum_wrapper.yum_input_loop()
