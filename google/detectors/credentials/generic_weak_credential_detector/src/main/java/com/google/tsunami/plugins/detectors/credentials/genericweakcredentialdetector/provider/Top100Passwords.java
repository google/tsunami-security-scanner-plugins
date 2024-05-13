/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider;

import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.CredentialType;
import com.google.tsunami.proto.NetworkService;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

/**
 * A very short list of the most used user names combined with the top 100 most used passwords.
 *
 * <p>List of user names is from <a
 * href="https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt">here</a>
 * and list of passwords is from <a
 * href="https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt">here</a>.
 */
public final class Top100Passwords extends CredentialProvider {

  private static final ImmutableList<String> TOP_USER_NAMES =
      ImmutableList.of(
          "anonymous",
          "root",
          "admin",
          "test",
          "guest",
          "info",
          "adm",
          "mysql",
          "postgres",
          "user",
          "administrator",
          "oracle",
          "ftp",
          "pi",
          "puppet",
          "ansible",
          "ec2-user",
          "vagrant",
          "azureuser",
          "cisco",
          "rstudio");

  private static final ImmutableList<String> TOP_100_PASSWORDS =
      ImmutableList.of(
          "",
          "root",
          "test",
          "123456",
          "password",
          "Password",
          "12345678",
          "qwerty",
          "123456789",
          "12345",
          "1234",
          "111111",
          "1234567",
          "dragon",
          "123123",
          "baseball",
          "abc123",
          "football",
          "monkey",
          "letmein",
          "696969",
          "shadow",
          "master",
          "666666",
          "qwertyuiop",
          "123321",
          "mustang",
          "1234567890",
          "michael",
          "654321",
          "pussy",
          "superman",
          "1qaz2wsx",
          "7777777",
          "fuckyou",
          "121212",
          "000000",
          "qazwsx",
          "123qwe",
          "killer",
          "trustno1",
          "jordan",
          "jennifer",
          "zxcvbnm",
          "asdfgh",
          "hunter",
          "buster",
          "soccer",
          "harley",
          "batman",
          "andrew",
          "tigger",
          "sunshine",
          "iloveyou",
          "fuckme",
          "2000",
          "charlie",
          "robert",
          "thomas",
          "hockey",
          "ranger",
          "daniel",
          "starwars",
          "klaster",
          "112233",
          "george",
          "asshole",
          "computer",
          "michelle",
          "jessica",
          "pepper",
          "1111",
          "zxcvbn",
          "555555",
          "11111111",
          "131313",
          "freedom",
          "777777",
          "pass",
          "fuck",
          "maggie",
          "159753",
          "aaaaaa",
          "ginger",
          "princess",
          "joshua",
          "cheese",
          "amanda",
          "summer",
          "love",
          "ashley",
          "6969",
          "nicole",
          "chelsea",
          "biteme",
          "matthew",
          "access",
          "yankees",
          "987654321",
          "dallas",
          "austin",
          "thunder",
          "taylor",
          "matrix");

  private final ImmutableList<TestCredential> credentials;

  public Top100Passwords() {
    this(TOP_USER_NAMES, TOP_100_PASSWORDS);
  }

  @VisibleForTesting
  Top100Passwords(List<String> usernameList, List<String> passwordList) {
    credentials =
        Lists.cartesianProduct(usernameList, passwordList).stream()
            .map(list -> TestCredential.create(list.get(0), Optional.of(list.get(1))))
            .collect(toImmutableList());
  }

  @Override
  public CredentialType type() {
    return CredentialType.TOP_100;
  }

  @Override
  public String name() {
    return "Top100Passwords";
  }

  @Override
  public String description() {
    return "Provides a list of the most common user names combined with the top 100 common"
        + " passwords";
  }

  @Override
  public Iterator<TestCredential> generateTestCredentials(NetworkService unused) {
    return credentials.iterator();
  }

  @Override
  // Top 100 passwords are tested after default credentials.
  public int priority() {
    return 2;
  }
}
