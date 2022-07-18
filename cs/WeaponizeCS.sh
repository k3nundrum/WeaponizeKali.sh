#!/usr/bin/env bash

nocolor="\033[0m"
green="\033[0;32m"
yellow="\033[0;33m"
red="\033[0;31m"
blue="\033[0;34m"
magenta_bold="\033[1;35m"

# -----------------------------------------------------------------------------
# ----------------------------------- Init ------------------------------------
# -----------------------------------------------------------------------------

filesystem() {
	mkdir Profiles Scripts Toolkits
}

# -----------------------------------------------------------------------------
# --------------------------------- Messages ----------------------------------
# -----------------------------------------------------------------------------

info() {
	echo -e "${blue}[*] $1${nocolor}"
}

success() {
	echo -e "${green}[+] $1${nocolor}"
}

warning() {
	echo -e "${yellow}[!] $1${nocolor}"
}

fail() {
	echo -e "${red}[-] $1${nocolor}"
}

progress() {
	echo -e "${magenta_bold}[WPNZKL] Installing $1${nocolor}"
}

# -----------------------------------------------------------------------------
# ---------------------------------- Helpers ----------------------------------
# -----------------------------------------------------------------------------

_pushd() {
	pushd $1 2>&1 > /dev/null
}

_popd() {
	popd 2>&1 > /dev/null
}

cloneRepository() {
	url=$1
	repo_name=${url##*/}
	repo_name=${repo_name%.*}

	if [ -z "$2" ]; then
		dname=$repo_name
	else
		dname=$2
	fi

	if git clone --recurse-submodules -q $url $dname; then
		success "Cloned repository: $repo_name"
	else
		fail "Failed to clone repository: $repo_name"
	fi
}

downloadRawFile() {
	url=$1
	filename=$2
	if curl -sSL $url -o $filename; then
		success "Downloaded raw file: $filename"
	else
		fail "Failed to download raw file: $filename"
	fi
}

downloadRelease() {
	full_repo_name=$1
	release_name=$2
	filename=$3
	if curl -sSL "https://api.github.com/repos/$full_repo_name/releases/latest" | jq -r '.assets[].browser_download_url' | grep $release_name | wget -O $filename -qi -; then
		success "Downloaded release: $filename"
	else
		fail "Failed to download release: $filename"
	fi
}

# -----------------------------------------------------------------------------
# ---------------------------------- Scripts ----------------------------------
# -----------------------------------------------------------------------------

BOFs() {
	_pushd Scripts
	progress "BOFs"
	cloneRepository "https://github.com/ajpc500/BOFs.git"
	_popd
}

BofRoast() {
	_pushd Scripts
	progress "BofRoast"
	cloneRepository "https://github.com/cube0x0/BofRoast.git"
	_popd
}

BokuLoader() {
	_pushd Scripts
	progress "BokuLoader"
	cloneRepository "https://github.com/boku7/BokuLoader.git"
	_popd
}

C2-Tool-Collection() {
	_pushd Scripts
	progress "C2-Tool-Collection"
	cloneRepository "https://github.com/outflanknl/C2-Tool-Collection.git"
	_popd
}

CS-Remote-OPs-BOF() {
	_pushd Scripts
	progress "CS-Remote-OPs-BOF"
	cloneRepository "https://github.com/trustedsec/CS-Remote-OPs-BOF.git"
	_popd
}

CS-Situational-Awareness-BOF() {
	_pushd Scripts
	progress "CS-Situational-Awareness-BOF"
	cloneRepository "https://github.com/trustedsec/CS-Situational-Awareness-BOF.git"
	#cd CS-Situational-Awareness-BOF
	#./make_all.sh
	_popd
}

DInjector() {
	_pushd Scripts
	progress "DInjector"
	cloneRepository "https://github.com/snovvcrash/DInjector.git"
	_popd
}

DelegationBOF() {
	_pushd Scripts
	progress "DelegationBOF"
	cloneRepository "https://github.com/IcebreakerSecurity/DelegationBOF.git"
	_popd
}

FindObjects-BOF() {
	_pushd Scripts
	progress "FindObjects-BOF"
	cloneRepository "https://github.com/outflanknl/FindObjects-BOF.git"
	_popd
}

HelpColor() {
	_pushd Scripts
	progress "HelpColor"
	cloneRepository "https://github.com/outflanknl/HelpColor.git"
	_popd
}

Invoke-CredentialPhisher() {
	_pushd Scripts
	progress "Invoke-CredentialPhisher"
	cloneRepository "https://github.com/fox-it/Invoke-CredentialPhisher.git"
	_popd
}

LdapSignCheck() {
	_pushd Scripts
	progress "LdapSignCheck"
	cloneRepository "https://github.com/cube0x0/LdapSignCheck.git"
	_popd
}

PersistBOF() {
	_pushd Scripts
	progress "PersistBOF"
	cloneRepository "https://github.com/IcebreakerSecurity/PersistBOF.git"
	_popd
}

PortBender() {
	_pushd Scripts
	progress "PortBender"
	cloneRepository "https://github.com/praetorian-inc/PortBender.git"
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/PortBender64.dll" PortBender/static/PortBender.dll
	_popd
}

RdpThief() {
	_pushd Scripts
	progress "RdpThief"
	cloneRepository "https://github.com/0x09AL/RdpThief.git"
	_popd
}

SyscallPack() {
	_pushd Scripts
	progress "SyscallPack"
	cloneRepository "https://github.com/cube0x0/SyscallPack.git"
	_popd
}

freeBokuLoader() {
	_pushd Scripts
	progress "freeBokuLoader"
	cloneRepository "https://github.com/S4ntiagoP/freeBokuLoader.git"
	_popd
}

inject-assembly() {
	_pushd Scripts
	progress "inject-assembly"
	cloneRepository "https://github.com/kyleavery/inject-assembly.git"
	_popd
}

injectAmsiBypass() {
	_pushd Scripts
	progress "injectAmsiBypass"
	cloneRepository "https://github.com/boku7/injectAmsiBypass.git"
	_popd
}

nanodump() {
	_pushd Scripts
	progress "nanodump"
	cloneRepository "https://github.com/helpsystems/nanodump.git"
	_popd
}

Scripts() {
	BOFs
	BofRoast
	BokuLoader
	C2-Tool-Collection
	CS-Remote-OPs-BOF
	CS-Situational-Awareness-BOF
	DInjector
	DelegationBOF
	FindObjects-BOF
	HelpColor
	Invoke-CredentialPhisher
	LdapSignCheck
	PersistBOF
	PortBender
	RdpThief
	SyscallPack
	freeBokuLoader
	inject-assembly
	injectAmsiBypass
	nanodump
}

# -----------------------------------------------------------------------------
# --------------------------------- Profiles ----------------------------------
# -----------------------------------------------------------------------------

BC-SECURITY-Malleable-C2-Profiles() {
	_pushd Profiles
	progress "BC-SECURITY-Malleable-C2-Profiles"
	cloneRepository "https://github.com/BC-SECURITY/Malleable-C2-Profiles.git"
	_popd
}

CobaltNotion() {
	_pushd Profiles
	progress "CobaltNotion"
	cloneRepository "https://github.com/HuskyHacks/CobaltNotion.git"
	_popd
}

minimal-defender-bypass() {
	_pushd Profiles
	progress "minimal-defender-bypass"
	cloneRepository "https://gist.github.com/tothi/8abd2de8f4948af57aa2d027f9e59efe.git" minimal-defender-bypass
	_popd
}

threatexpress-malleable-c2() {
	_pushd Profiles
	progress "threatexpress-malleable-c2"
	cloneRepository "https://github.com/threatexpress/malleable-c2.git"
	_popd
}

Profiles() {
	BC-SECURITY-Malleable-C2-Profiles
	CobaltNotion
	minimal-defender-bypass
	threatexpress-malleable-c2
}

# -----------------------------------------------------------------------------
# ----------------------------------- Main ------------------------------------
# -----------------------------------------------------------------------------

filesystem
Scripts
Profiles
