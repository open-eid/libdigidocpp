Name: libdigidocpp
Version: 3.8
Release: 1%{?dist}
Summary: DigiDocPP library
Group: System Environment/Libraries
License: LGPLv2+
URL: http://www.ria.ee		
Source0: libdigidocpp.tar.gz
BuildRoot: %{_tmppath}/-%{version}-%{release}-root-%(%{__id_u} -n)
%if 0%{?fedora}
BuildRequires: xml-security-c-devel, xsd
%endif
BuildRequires: gcc-c++, libdigidoc-devel
Requires: libdigidoc => 3.8
%description
Library for creating DigiDoc files

%if %{defined suse_version}
%debug_package
%endif

%package devel
Summary: DigiDocPP library devel files
Group: System Environment/Libraries
Requires: %{name}%{?_isa} = %{version}-%{release}, libdigidoc-devel, esteidcerts-devel
%description devel
Devel files for DigiDocPP library


%prep
%setup -q -n %{name}
cmake . \
 -DCMAKE_BUILD_TYPE=RelWithDebInfo \
 -DCMAKE_INSTALL_PREFIX=/usr \
 -DCMAKE_INSTALL_SYSCONFDIR=/etc \
 -DCERTS_LOCATION=/usr/share/esteid/certs \
 -DCMAKE_VERBOSE_MAKEFILE=ON \
 -DSWIG_EXECUTABLE=SWIG_EXECUTABLE-NOTFOUND

%build
make

%install
rm -rf %{buildroot}
cd %{_builddir}/%{name}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}
cd %{_builddir}/%{name}
make clean

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/*.so.*
%{_mandir}
%config(noreplace) %{_sysconfdir}/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/*

%changelog
* Fri Aug 13 2010 RIA <info@ria.ee> 1.0-1
- first build no changes

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
