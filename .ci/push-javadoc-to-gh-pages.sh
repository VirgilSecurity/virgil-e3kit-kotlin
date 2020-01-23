#!/usr/bin/env bash
#
# Copyright (C) 2015-2019 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

get_version () {
  filename=$1 # Get first parameter as filename
  local  __resultvar=$2 #  Get second parameter to return result

  version="-1"

  while read line; do

    firstWord="$(cut -d'=' -f1 <<< "$line")"

    if [[ "$firstWord" = "final String SDK_VERSION " ]];
    then
      version="$(cut -d"'" -f2 <<< "$line")"
    fi

  done < ${filename}

  if [[ "$__resultvar" ]]; then
    eval ${__resultvar}="${version}"
  else
    echo "${version}"
  fi
}

generate_index_page() {
  cat >"index.html" << EOL
  <html>
  <head>
    <meta charset="utf-8">
    <title>Virgil Security E3Kit Java/Kotlin</title>
  </head>
  <body style="display: flex; align-items: center; flex-direction: column;">

    <img style="display: block; margin-left: auto; margin-right: auto;" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" width="230px" hspace="10" vspace="6" />

    <div style="width: r00px">
      <h1>Virgil Security E3Kit JavaDoc</h1>
      <p>&nbsp;</p>

      <h2 style="color:#110B91B0;">User modules</h2>
      <hr/>
      <h3>E3Kit</h3>
      <ul><li><a href="content/ethree-kotlin/${2}/ethree-kotlin/index.html">${2}</a></li></ul>

      <h3>E3Kit Enclave</h3>
      <ul><li><a href="content/ethree-enclave/${3}/ethree-enclave/index.html">${3}</a></li></ul>

      <p>&nbsp;</p>
      <h2 style="color:#110B91B1;">Internal modules</h2>
      <hr/>

      <h3>E3Kit Common</h3>
      <ul><li><a href="content/ethree-common/${1}/ethree-common/index.html">${1}</a></li></ul>
    </div>

    <p>&nbsp;</p>
    <p style="text-align: center">
      <a href="https://virgilsecurity.com">Virgil Security, Inc.</a> | <a href="https://github.com/VirgilSecurity/virgil-e3kit-kotlin">E3Kit Github</a>
    </p>
  </body>
  </html>
EOL
}

if [[ "$TRAVIS_REPO_SLUG" == "VirgilSecurity/virgil-e3kit-kotlin" ]] && [[ "$TRAVIS_PULL_REQUEST" == "false" ]] && ([[ "$TRAVIS_BRANCH" == "master" ]] || [[ "$TRAVIS_BRANCH" == "fix/gh-pages" ]]); then

  echo -e "Publishing javadoc...\n"

  # Generate docs
  ./gradlew :ethree-common:javadocJar
  ./gradlew :ethree-kotlin:javadocJar
  ./gradlew :ethree-enclave:javadocJar

  version="-1"

  # Get each module version
  get_version "build.gradle" version

  # Folder names with module name and version
  commonFolder="common_v${version}"
  kotlinFolder="kotlin_v${version}"
  enclaveFolder="enclave_v${version}"

  # Create each module docs temporary folder
  mkdir $HOME/javadoc-latest/
  mkdir $HOME/javadoc-latest/${commonFolder}/
  mkdir $HOME/javadoc-latest/${kotlinFolder}/
  mkdir $HOME/javadoc-latest/${enclaveFolder}/
  cp -R ethree-common/build/javadoc/. $HOME/javadoc-latest/${commonFolder}/
  cp -R ethree-kotlin/build/javadoc/. $HOME/javadoc-latest/${kotlinFolder}/
  cp -R ethree-enclave/build/javadoc/. $HOME/javadoc-latest/${enclaveFolder}/

  # Get last gh-pages docs
  cd $HOME
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "travis-ci"
  git clone --quiet --branch=gh-pages https://${GH_TOKEN}@github.com/VirgilSecurity/virgil-e3kit-kotlin gh-pages > /dev/null

  # Remove old docs
  cd gh-pages
  git rm index.html
  git rm -rf content

  # Create main index page for all modules
  folders=(${commonFolder} ${kotlinFolder} ${enclaveFolder})
  generate_index_page ${folders[*]}

  # Move each module docs to actual folder
  mkdir content
  mkdir content/ethree-common/
  mkdir content/ethree-kotlin/
  mkdir content/ethree-enclave/
  mv $HOME/javadoc-latest/${commonFolder} content/ethree-common/
  mv $HOME/javadoc-latest/${kotlinFolder} content/ethree-kotlin/
  mv $HOME/javadoc-latest/${enclaveFolder} content/ethree-enclave/

  # Add new docs to index and commit
  git add -f .
  git commit -m "Latest javadoc on successful travis build $TRAVIS_BUILD_NUMBER auto-pushed to gh-pages"
  git push -fq origin gh-pages > /dev/null

  echo -e "Published Javadoc to gh-pages.\n"
fi
