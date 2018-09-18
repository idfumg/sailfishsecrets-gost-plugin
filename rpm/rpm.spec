Name: omp-sailfishsecrets-gost-plugin
Summary: Sailfish secrets plugin for gost algorithms
Version: 0.1.0
Release: 1
Group: System/Libraries
License: Proprietary
BuildRequires: pkgconfig(Qt5Core)
BuildRequires: pkgconfig(sailfishcrypto)
BuildRequires: pkgconfig(sailfishcryptopluginapi)
Requires: sailfishsecretsdaemon >= 0.1.18
Requires: libsailfishcrypto >= 0.1.18
Requires: libsailfishcryptopluginapi >= 0.1.18
Source0: %{name}-%{version}.tar.bz2

%description
%{summary}

%prep
%setup -q -n %{name}-%{version}

%build
%qmake5 "VERSION=%{version}"
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%qmake5_install

%files
%defattr(-,root,root,-)
%{_libdir}/Sailfish/Crypto/libsailfishgostplugin.so

%post
systemctl-user daemon-reload || :
/sbin/ldconfig || :

%postun
/sbin/ldconfig || :
