%define initdir %{_initddir}
%define udevrulesdir /lib/udev/rules.d

Name: systemtap
Version: 3.0
Release: 1%{?dist}
# for version, see also configure.ac

# Packaging abstract:
#
# systemtap              empty req:-client req:-devel
# systemtap-server       /usr/bin/stap-server*, req:-devel
# systemtap-devel        /usr/bin/stap, runtime, tapset, req:kernel-devel
# systemtap-runtime      /usr/bin/staprun, /usr/bin/stapsh, /usr/bin/stapdyn
# systemtap-client       /usr/bin/stap, samples, docs, tapset(bonus), req:-runtime
# systemtap-initscript   /etc/init.d/systemtap, req:systemtap
# systemtap-sdt-devel    /usr/include/sys/sdt.h /usr/bin/dtrace
# systemtap-testsuite    /usr/share/systemtap/testsuite*, req:systemtap, req:sdt-devel
# systemtap-runtime-virtguest udev rules, init scripts/systemd service, req:-runtime
#
# Typical scenarios:
#
# stap-client:           systemtap-client
# stap-server:           systemtap-server
# local user:            systemtap
#
# Unusual scenarios:
#
# intermediary stap-client for --remote:       systemtap-client (-runtime unused)
# intermediary stap-server for --use-server:   systemtap-server (-devel unused)

Summary: Programmable system-wide instrumentation system
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Source: ftp://sourceware.org/pub/systemtap/releases/systemtap-%{version}.tar.gz

# Build*
BuildRequires: gcc-c++
BuildRequires: pkgconfig(popt)
BuildRequires: gettext-devel
BuildRequires: pkgconfig
BuildRequires: pkgconfig(nss)
BuildRequires: pkgconfig(sqlite3)
# Needed for libstd++ < 4.0, without <tr1/memory>
BuildRequires: pkgconfig(rpm) glibc-headers
BuildRequires: elfutils-devel >= 0.142
BuildRequires: readline-devel
BuildRequires: ncurses-devel

BuildRequires: systemd

# Install requirements
Requires: systemtap-client = %{version}-%{release}
Requires: systemtap-devel = %{version}-%{release}
Source100: systemtap-rpmlintrc

%description
SystemTap is an instrumentation system for systems running Linux.
Developers can write instrumentation scripts to collect data on
the operation of the system.  The base systemtap package contains/requires
the components needed to locally develop and execute systemtap scripts.

# ------------------------------------------------------------------------

%package server
Summary: Instrumentation System Server
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Requires: systemtap-devel = %{version}-%{release}
# On RHEL[45], /bin/mktemp comes from the 'mktemp' package.  On newer
# distributions, /bin/mktemp comes from the 'coreutils' package.  To
# avoid a specific RHEL[45] Requires, we'll do a file-based require.
Requires: nss /bin/mktemp
Requires: zip unzip
Requires(pre): shadow-utils
BuildRequires: pkgconfig(nss)
Requires: systemd

%description server
This is the remote script compilation server component of systemtap.
It announces itself to nearby clients with avahi (if available), and
compiles systemtap scripts to kernel objects on their demand.

%package devel
Summary: Programmable system-wide instrumentation system - development headers, tools
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
# Alternate kernel packages kernel-PAE-devel et al. have a virtual
# provide for kernel-devel, so this requirement does the right thing,
# at least past RHEL4.
Requires: kernel-devel
Requires: gcc make
# Suggest: kernel-debuginfo

%description devel
This package contains the components needed to compile a systemtap
script from source form into executable (.ko) forms.  It may be
installed on a self-contained developer workstation (along with the
systemtap-client and systemtap-runtime packages), or on a dedicated
remote server (alongside the systemtap-server package).  It includes
a copy of the standard tapset library and the runtime library C files.

%package runtime
Summary: Programmable system-wide instrumentation system - runtime
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Requires(pre): shadow-utils

%description runtime
SystemTap runtime contains the components needed to execute
a systemtap script that was already compiled into a module
using a local or remote systemtap-devel installation.

%package client
Summary: Programmable system-wide instrumentation system - client
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Requires: zip unzip
Requires: systemtap-runtime = %{version}-%{release}
Requires: coreutils grep sed unzip zip
Requires: openssh-clients

%description client
This package contains/requires the components needed to develop
systemtap scripts, and compile them using a local systemtap-devel
or a remote systemtap-server installation, then run them using a
local or remote systemtap-runtime.  It includes script samples and
documentation, and a copy of the tapset library for reference.

%package initscript
Summary: Systemtap Initscripts
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Requires: systemtap = %{version}-%{release}
%description initscript
This package includes a SysVinit script to launch selected systemtap
scripts at system startup.

%package sdt-devel
Summary: Static probe support tools
Group: Development/System
License: GPLv2+ and Public Domain
URL: http://sourceware.org/systemtap/

%description sdt-devel
This package includes the <sys/sdt.h> header file used for static
instrumentation compiled into userspace programs and libraries, along
with the optional dtrace-compatibility preprocessor to process related
.d files into tracing-macro-laden .h headers.

%package testsuite
Summary: Instrumentation System Testsuite
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Requires: systemtap = %{version}-%{release}
Requires: systemtap-sdt-devel = %{version}-%{release}
Requires: systemtap-server = %{version}-%{release}
Requires: dejagnu which elfutils grep nc
Requires: gcc gcc-c++ make glibc-devel
# testsuite/systemtap.base/ptrace.exp needs strace
Requires: strace
# testsuite/systemtap.base/ipaddr.exp needs nc. Unfortunately, the rpm
# that provides nc has changed over time (from 'nc' to
# 'nmap-ncat'). So, we'll do a file-based require.
Requires: /usr/bin/nc
Requires: prelink
# The following "meta" files for the systemtap examples run "perf":
#   testsuite/systemtap.examples/hw_watch_addr.meta
#   testsuite/systemtap.examples/memory/hw_watch_sym.meta
Requires: perf

%description testsuite
This package includes the dejagnu-based systemtap stress self-testing
suite.  This may be used by system administrators to thoroughly check
systemtap on the current system.

%package runtime-virtguest
Summary: Systemtap Cross-VM Instrumentation - guest
Group: Development/System
License: GPLv2+
URL: http://sourceware.org/systemtap/
Requires: systemtap-runtime = %{version}-%{release}
Requires(post): findutils coreutils
Requires(preun): grep coreutils
Requires(postun): grep coreutils

%description runtime-virtguest
This package installs the services necessary on a virtual machine for a
systemtap-runtime-virthost machine to execute systemtap scripts.

# ------------------------------------------------------------------------

%prep
%setup -q -n %{name}-%{version}/systemtap

%build
%configure			\
	--without-dyninst	\
	--enable-sqlite		\
	--disable-crash		\
	--disable-docs		\
	--enable-pie		\
	--with-rpm		\
	--disable-virt		\
	--without-python3	\
	--disable-silent-rules	\
	--with-extra-version="rpm %{version}-%{release}"
make %{?_smp_mflags}

%install
rm -rf ${RPM_BUILD_ROOT}
make DESTDIR=$RPM_BUILD_ROOT install
%find_lang %{name}
for dir in $(ls -1d $RPM_BUILD_ROOT%{_mandir}/{??,??_??}) ; do
    dir=$(echo $dir | sed -e "s|^$RPM_BUILD_ROOT||")
    lang=$(basename $dir)
    echo "%%lang($lang) $dir/man*/*" >> %{name}.lang
done

# We want the examples in the special doc dir, not the build install dir.
# We build it in place and then move it away so it doesn't get installed
# twice. rpm can specify itself where the (versioned) docs go with the
# %doc directive.
mv $RPM_BUILD_ROOT%{_datadir}/doc/systemtap/examples examples

# Fix permissions.
chmod -x examples/interrupt/interrupts-by-dev.txt

# Fix paths in the example scripts.
find examples -type f -name '*.stp' -print0 | xargs -0 sed -i -r -e '1s@^#!.+stap@#!%{_bindir}/stap@'

# To make rpmlint happy, remove any .gitignore files in the testsuite.
find testsuite -type f -name '.gitignore' -print0 | xargs -0 rm -f

# Because "make install" may install staprun with whatever mode, the
# post-processing programs rpmbuild runs won't be able to read it.
# So, we change permissions so that they can read it.  We'll set the
# permissions back to 04110 in the %files section below.
chmod 755 $RPM_BUILD_ROOT%{_bindir}/staprun

#install the useful stap-prep script
install -c -m 755 stap-prep $RPM_BUILD_ROOT%{_bindir}/stap-prep

# Copy over the testsuite
cp -rp testsuite $RPM_BUILD_ROOT%{_datadir}/systemtap

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/stap-server
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/stap-server
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/stap-server/.systemtap
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/stap-server
touch $RPM_BUILD_ROOT%{_localstatedir}/log/stap-server/log
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/cache/systemtap
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/run/systemtap
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
install -m 644 initscript/logrotate.stap-server $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/stap-server
mkdir -p $RPM_BUILD_ROOT%{initdir}
install -m 755 initscript/systemtap $RPM_BUILD_ROOT%{initdir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/systemtap
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/systemtap/conf.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/systemtap/script.d
install -m 644 initscript/config.systemtap $RPM_BUILD_ROOT%{_sysconfdir}/systemtap/config
mkdir -p $RPM_BUILD_ROOT%{_unitdir}
touch $RPM_BUILD_ROOT%{_unitdir}/stap-server.service
install -m 644 stap-server.service $RPM_BUILD_ROOT%{_unitdir}/stap-server.service
mkdir -p $RPM_BUILD_ROOT%{_tmpfilesdir}
install -m 644 stap-server.conf $RPM_BUILD_ROOT%{_tmpfilesdir}/stap-server.conf

mkdir -p $RPM_BUILD_ROOT%{udevrulesdir}
install -p -m 644 staprun/guest/99-stapsh.rules $RPM_BUILD_ROOT%{udevrulesdir}
mkdir -p $RPM_BUILD_ROOT%{_unitdir}
install -p -m 644 staprun/guest/stapsh@.service $RPM_BUILD_ROOT%{_unitdir}

%clean
rm -rf ${RPM_BUILD_ROOT}

%pre runtime
getent group stapusr >/dev/null || groupadd -g 156 -r stapusr 2>/dev/null || groupadd -r stapusr
getent group stapsys >/dev/null || groupadd -g 157 -r stapsys 2>/dev/null || groupadd -r stapsys
getent group stapdev >/dev/null || groupadd -g 158 -r stapdev 2>/dev/null || groupadd -r stapdev
exit 0

%pre server
getent group stap-server >/dev/null || groupadd -g 155 -r stap-server 2>/dev/null || groupadd -r stap-server
getent passwd stap-server >/dev/null || \
  useradd -c "Systemtap Compile Server" -u 155 -g stap-server -d %{_localstatedir}/lib/stap-server -r -s /sbin/nologin stap-server 2>/dev/null || \
  useradd -c "Systemtap Compile Server" -g stap-server -d %{_localstatedir}/lib/stap-server -r -s /sbin/nologin stap-server

%post server

# We have some duplication between the %files listings for the
# ~stap-server directories and the explicit mkdir/chown/chmod bits
# here.  Part of the reason may be that a preexisting stap-server
# account may well be placed somewhere other than
# %{_localstatedir}/lib/stap-server, but we'd like their permissions
# set similarly.

test -e ~stap-server && chmod 750 ~stap-server

if [ ! -f ~stap-server/.systemtap/rc ]; then
  mkdir -p ~stap-server/.systemtap
  chown stap-server:stap-server ~stap-server/.systemtap
  # PR16276: guess at a reasonable number for a default --rlimit-nproc
  numcpu=`/usr/bin/getconf _NPROCESSORS_ONLN`
  if [ -z "$numcpu" -o "$numcpu" -lt 1 ]; then numcpu=1; fi
  nproc=`expr $numcpu \* 30`
  echo "--rlimit-as=614400000 --rlimit-cpu=60 --rlimit-nproc=$nproc --rlimit-stack=1024000 --rlimit-fsize=51200000" > ~stap-server/.systemtap/rc
  chown stap-server:stap-server ~stap-server/.systemtap/rc
fi

test -e %{_localstatedir}/log/stap-server/log || {
     touch %{_localstatedir}/log/stap-server/log
     chmod 644 %{_localstatedir}/log/stap-server/log
     chown stap-server:stap-server %{_localstatedir}/log/stap-server/log
}
# If it does not already exist, as stap-server, generate the certificate
# used for signing and for ssl.
if test ! -e ~stap-server/.systemtap/ssl/server/stap.cert; then
   runuser -s /bin/sh - stap-server -c %{_libexecdir}/systemtap/stap-gen-cert >/dev/null
fi
# Prepare the service
     # Note, Fedora policy doesn't allow network services enabled by default
     # /bin/systemctl enable stap-server.service >/dev/null 2>&1 || :
     /bin/systemd-tmpfiles --create %{_tmpfilesdir}/stap-server.conf >/dev/null 2>&1 || :
exit 0

%triggerin client -- systemtap-server
if test -e ~stap-server/.systemtap/ssl/server/stap.cert; then
   # echo Authorizing ssl-peer/trusted-signer certificate for local systemtap-server
   %{_libexecdir}/systemtap/stap-authorize-cert ~stap-server/.systemtap/ssl/server/stap.cert %{_sysconfdir}/systemtap/ssl/client >/dev/null
   %{_libexecdir}/systemtap/stap-authorize-cert ~stap-server/.systemtap/ssl/server/stap.cert %{_sysconfdir}/systemtap/staprun >/dev/null
fi
exit 0
# XXX: corresponding %triggerun?

%preun server
# Check that this is the actual deinstallation of the package, as opposed to
# just removing the old package on upgrade.
if [ $1 = 0 ] ; then
       /bin/systemctl --no-reload disable stap-server.service >/dev/null 2>&1 || :
       /bin/systemctl stop stap-server.service >/dev/null 2>&1 || :
fi
exit 0

%postun server
# Check whether this is an upgrade of the package.
# If so, restart the service if it's running
if [ "$1" -ge "1" ] ; then
        /bin/systemctl condrestart stap-server.service >/dev/null 2>&1 || :
fi
exit 0

%post initscript
    /bin/systemctl enable systemtap.service >/dev/null 2>&1 || :
exit 0

%preun initscript
# Check that this is the actual deinstallation of the package, as opposed to
# just removing the old package on upgrade.
if [ $1 = 0 ] ; then
        /bin/systemctl --no-reload disable systemtap.service >/dev/null 2>&1 || :
        /bin/systemctl stop systemtap.service >/dev/null 2>&1 || :
fi
exit 0

%postun initscript
# Check whether this is an upgrade of the package.
# If so, restart the service if it's running
if [ "$1" -ge "1" ] ; then
        /bin/systemctl condrestart systemtap.service >/dev/null 2>&1 || :
fi
exit 0

%post runtime-virtguest
   # Start services if there are ports present
   if [ -d /dev/virtio-ports ]; then
      (find /dev/virtio-ports -iname 'org.systemtap.stapsh.[0-9]*' -type l \
         | xargs -n 1 basename \
         | xargs -n 1 -I {} /bin/systemctl start stapsh@{}.service) >/dev/null 2>&1 || :
   fi
exit 0

%preun runtime-virtguest
# Stop service if this is an uninstall rather than an upgrade
if [ $1 = 0 ]; then
      # We need to stop all stapsh services. Because they are instantiated from
      # a template service file, we can't simply call disable. We need to find
      # all the running ones and stop them all individually
      for service in `/bin/systemctl --full | grep stapsh@ | cut -d ' ' -f 1`; do
         /bin/systemctl stop $service >/dev/null 2>&1 || :
      done
fi
exit 0

%postun runtime-virtguest
# Restart service if this is an upgrade rather than an uninstall
if [ "$1" -ge "1" ]; then
      # We need to restart all stapsh services. Because they are instantiated from
      # a template service file, we can't simply call restart. We need to find
      # all the running ones and restart them all individually
      for service in `/bin/systemctl --full | grep stapsh@ | cut -d ' ' -f 1`; do
         /bin/systemctl condrestart $service >/dev/null 2>&1 || :
      done
fi
exit 0

%post
# Remove any previously-built uprobes.ko materials
(make -C %{_datadir}/systemtap/runtime/uprobes clean) >/dev/null 2>&1 || true
(/sbin/rmmod uprobes) >/dev/null 2>&1 || true

%preun
# Ditto
(make -C %{_datadir}/systemtap/runtime/uprobes clean) >/dev/null 2>&1 || true
(/sbin/rmmod uprobes) >/dev/null 2>&1 || true

# ------------------------------------------------------------------------

%files -f systemtap.lang
# The master "systemtap" rpm doesn't include any files.

%files server -f systemtap.lang
%defattr(-,root,root)
%{_bindir}/stap-server
%dir %{_libexecdir}/systemtap
%{_libexecdir}/systemtap/stap-serverd
%{_libexecdir}/systemtap/stap-start-server
%{_libexecdir}/systemtap/stap-stop-server
%{_libexecdir}/systemtap/stap-gen-cert
%{_libexecdir}/systemtap/stap-sign-module
%{_libexecdir}/systemtap/stap-authorize-cert
%{_libexecdir}/systemtap/stap-env
%{_mandir}/man7/error*
%{_mandir}/man7/stappaths.7*
%{_mandir}/man7/warning*
%{_mandir}/man8/stap-server.8*
%{_unitdir}/stap-server.service
%{_tmpfilesdir}/stap-server.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/stap-server
%dir %{_sysconfdir}/stap-server
%dir %attr(0750,stap-server,stap-server) %{_localstatedir}/lib/stap-server
%dir %attr(0700,stap-server,stap-server) %{_localstatedir}/lib/stap-server/.systemtap
%dir %attr(0755,stap-server,stap-server) %{_localstatedir}/log/stap-server
%ghost %config(noreplace) %attr(0644,stap-server,stap-server) %{_localstatedir}/log/stap-server/log
%ghost %attr(0755,stap-server,stap-server) %{_localstatedir}/run/stap-server
%doc README README.unprivileged AUTHORS NEWS
%{!?_licensedir:%global license %%doc}
%license COPYING

%files devel -f systemtap.lang
%{_bindir}/stap
%{_bindir}/stap-prep
%{_bindir}/stap-report
%dir %{_datadir}/systemtap
%{_datadir}/systemtap/runtime
%{_datadir}/systemtap/tapset
%{_mandir}/man1/stap.1*
%{_mandir}/man1/stap-prep.1*
%{_mandir}/man1/stap-report.1*
%{_mandir}/man7/error*
%{_mandir}/man7/stappaths.7*
%{_mandir}/man7/warning*
%doc README README.unprivileged AUTHORS NEWS
%{!?_licensedir:%global license %%doc}
%license COPYING

%files runtime -f systemtap.lang
%defattr(-,root,root)
%attr(4110,root,stapusr) %{_bindir}/staprun
%{_bindir}/stapsh
%{_bindir}/stap-merge
%{_bindir}/stap-report
%dir %{_libexecdir}/systemtap
%{_libexecdir}/systemtap/stapio
%{_libexecdir}/systemtap/stap-authorize-cert
%{_mandir}/man1/stap-report.1*
%{_mandir}/man7/error*
%{_mandir}/man7/stappaths.7*
%{_mandir}/man7/warning*
%{_mandir}/man8/stapsh.8*
%{_mandir}/man8/staprun.8*
%doc README README.security AUTHORS NEWS
%{!?_licensedir:%global license %%doc}
%license COPYING

%files client -f systemtap.lang
%defattr(-,root,root)
%doc README README.unprivileged AUTHORS NEWS examples
%{!?_licensedir:%global license %%doc}
%license COPYING
%{_bindir}/stap
%{_bindir}/stap-prep
%{_bindir}/stap-report
%{_mandir}/man1/stap.1*
%{_mandir}/man1/stap-prep.1*
%{_mandir}/man1/stap-merge.1*
%{_mandir}/man1/stap-report.1*
%{_mandir}/man1/stapref.1*
%{_mandir}/man3/*
%{_mandir}/man7/error*
%{_mandir}/man7/stappaths.7*
%{_mandir}/man7/warning*
%dir %{_datadir}/systemtap
%{_datadir}/systemtap/tapset

%files initscript
%defattr(-,root,root)
%{initdir}/systemtap
%dir %{_sysconfdir}/systemtap
%dir %{_sysconfdir}/systemtap/conf.d
%dir %{_sysconfdir}/systemtap/script.d
%config(noreplace) %{_sysconfdir}/systemtap/config
%dir %{_localstatedir}/cache/systemtap
%ghost %{_localstatedir}/run/systemtap
%{_mandir}/man8/systemtap.8*

%files sdt-devel
%defattr(-,root,root)
%{_bindir}/dtrace
%{_includedir}/sys/sdt.h
%{_includedir}/sys/sdt-config.h
%{_mandir}/man1/dtrace.1*
%doc README AUTHORS NEWS
%{!?_licensedir:%global license %%doc}
%license COPYING

%files testsuite
%defattr(-,root,root)
%dir %{_datadir}/systemtap
%{_datadir}/systemtap/testsuite

%files runtime-virtguest
%{udevrulesdir}/99-stapsh.rules
%{_unitdir}/stapsh@.service
