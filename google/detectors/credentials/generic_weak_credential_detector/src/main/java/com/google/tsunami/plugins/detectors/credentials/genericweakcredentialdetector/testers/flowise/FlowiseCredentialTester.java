/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.flowise;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.ByteString;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.Set;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/** Credential tester specifically for flowise. */
public final class FlowiseCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;
  
  // Flowise targeted pages and expected content
  private static final String FLOWISE_AUTH_URL = "sign-up";
  private static final String FLOWISE_AUTHAPI_URL = "api/v1/auth/login";
  private static final String FLOWISE_AUTH_EXPECTED_TITLE = "flowise";
  private static final Set<String> FLOWISE_AUTHAPI_EXPECTED_JSONKEYS_ONFAILURE = new HashSet<>(Set.of("statusCode","success","message","stack"));
  private static final Set<String> FLOWISE_AUTHAPI_EXPECTED_JSONKEYS_ONSUCCESS = new HashSet<>(Set.of("id","email"));
  private static final String FLOWISE_AUTHAPI_JSONKEY_MSG = "message";
  private static final String FLOWISE_AUTHAPI_JSONVAL_MSG_USERNOTFOUND = "User Not Found";
  // Ensures that candidates respect the username/password policies
  private static final boolean FLOWISE_POLICY_FORCE = true; // If true, transforms passwords to match policy; else ignore bad candidates
  private static final String FLOWISE_POLICY_EMAIL_APPEND_DOMAIN = "@localhost.lan";
  private static final String FLOWISE_POLICY_PASSWORD_APPEND_DIGIT = "1";
  private static final String FLOWISE_POLICY_PASSWORD_APPEND_SPECIALCHAR = "!";
  // Cache
  private Set<String> cache_badUsernames = new HashSet<>();
  private Set<TestCredential> cache_badCredentials = new HashSet<>();
  private Set<TestCredential> cache_foundCredentials = new HashSet<>();

  @Inject
  FlowiseCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "FlowiseCredentialTester";
  }

  @Override
  public String description() {
    return "Flowise credential tester.";
  }
  
  @Override
  public boolean batched() {
    return true;
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
	// NetworkServiceUtils.getWebServiceName(networkService) returns "ppp" (not relevant for checking if Flowise is present)
	
	if (NetworkServiceUtils.isWebService(networkService)) {
      var urlAuth =
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + FLOWISE_AUTH_URL;
      var urlAuthApi =
          NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + FLOWISE_AUTHAPI_URL;
          
      try {
        logger.atInfo().log("Probing Flowise auth page...");

        // Checking page title
        HttpResponse authResponse =
            httpClient.send(get(urlAuth).withEmptyHeaders().build());
          
        String authTitle = FlowiseHttpResponseUtil.from(authResponse).getTitleStr();

        if (authResponse.status().isSuccess() && Ascii.toLowerCase(authTitle).contains(FLOWISE_AUTH_EXPECTED_TITLE)) {
	      // Checking auth response format
          HttpResponse authApiResponse =
		      this.sendAuthRequest(urlAuthApi, "a", "b");
		  
		  String authApiBody = FlowiseHttpResponseUtil.from(authApiResponse).getBodyStr();
		  
		  // Retrieving all keys in JSON object
		  try {
            Set<String> jsonKeys = this.getJsonKeys(authApiBody);
            
            if (jsonKeys.containsAll(FLOWISE_AUTHAPI_EXPECTED_JSONKEYS_ONFAILURE)) {
	          logger.atInfo().log("Detected Flowise authentication!");
		      return true;
		    }
		  } catch (JsonSyntaxException e) {
            return false; // Valid JSON format expected in auth response body
          }
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Flowise: Failed HTTP Request");
        return false;
      }
    }

    return false;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    return credentials.stream()
        .filter(cred -> isCredentialValid(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isCredentialValid(NetworkService networkService, TestCredential credential) {
    var urlAuthApi =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + FLOWISE_AUTHAPI_URL;
    
    String email = credential.username();
    String password = credential.password().orElse("");
    
    // Flowise does not allow empty login/password, no need to test it
    if (email.isEmpty() || password.isEmpty()) {
      return false; 
	}
	// Ensuring the email is in a valid format
    if (FlowiseValdationUtil.isInvalidEmail(email)) {
      email = FlowiseValdationUtil.upgradeToValidEmail(email);
      if (email.isEmpty() || !FLOWISE_POLICY_FORCE) {
        return false;
      }
	}
	// Ensuring the password respects the policy
	if (FlowiseValdationUtil.isInvalidPassword(password)) {
      password = FlowiseValdationUtil.upgradeToValidPassword(password);
      if (password.isEmpty() || !FLOWISE_POLICY_FORCE) {
        return false;
      }
	}
	// Update credential (email or password may have changed)
	credential = TestCredential.create(email, Optional.of(password));
	
	// ------ CACHE 
	// Aborts if the app explicitely stated that the user does not exist (user enumeration)
	if (this.cache_badUsernames.contains(email)) {
		return false;
	}
	// Or if the creds have already been tested and failed
	if (this.cache_badCredentials.contains(credential)) {
		return false;
	}
	// If user has already been found
	final String finalEmail = email; // lambda functions requires a final local variable
	if (this.cache_foundCredentials.stream().filter(cred -> cred.username().equals(finalEmail)).count() > 0) {
		// Return TRUE if the password matches, else FALSE
		return (this.cache_foundCredentials.contains(credential));
	}
	
    // Authenticate
    try {
      HttpResponse authApiResponse = sendAuthRequest(urlAuthApi, email, password);
      logger.atInfo().log(
        "Testing Creds on Flowise - url: %s, username: %s, password: %s",
        urlAuthApi, email, password);
        
        return isUserAuthenticated(authApiResponse, credential);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Flowise: Failed Authentication HTTP Request");
      return false;
    }
  }
  
  private HttpResponse sendAuthRequest(String url, String email, String password) throws IOException {
	URL urlObj = new URL(url);
	
    Map<String, String> jsonParams = new HashMap<>();
    jsonParams.put("email", email);
    jsonParams.put("password", password);
    
    byte[] postData = new Gson().toJson(jsonParams).getBytes(UTF_8);

    HttpRequest req = post(url)
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader("Host", urlObj.getHost() + ":" + urlObj.getPort())
                        .addHeader("Accept", "application/json, text/plain, */*")
                        .addHeader("Content-Type", "application/json")
                        .addHeader("Connection", "close")
                        .build())
                .setRequestBody(ByteString.copyFrom(postData))
                .build();

    return httpClient
        .modify()
        .setFollowRedirects(false)
        .build()
        .send(req);
  }
  
  private boolean isUserAuthenticated(HttpResponse response, TestCredential credential) throws IOException {
    try {
	  String authApiBody = FlowiseHttpResponseUtil.from(response).getBodyStr();
	  Set<String> jsonKeys = this.getJsonKeys(authApiBody);
	    
	  // Authenticated
	  if (response.status().equals(HttpStatus.OK) && jsonKeys.containsAll(FLOWISE_AUTHAPI_EXPECTED_JSONKEYS_ONSUCCESS)) {
	    logger.atInfo().log("Found valid Flowise credentials!");
	    this.cache_foundCredentials.add(credential); // Only one password can be used by an account, no need to test the remaining
	    return true;
	  }
	  
	  // Not authenticated = Bad credentials
	  this.cache_badCredentials.add(credential);
	  
	  // Flowise authentication appears to be vulnerable to user enumeration
	  // Taking advantage of this to optimize the bruteforce attack
	  // See https://github.com/FlowiseAI/Flowise/blob/6c78e1c36f4cf08874b9b7a444d61ab63441d78a/packages/server/src/enterprise/services/account.service.ts#L466
	  if (jsonKeys.containsAll(FLOWISE_AUTHAPI_EXPECTED_JSONKEYS_ONFAILURE)) {
		String errorMessage = this.getJsonStr(this.getJsonObject(authApiBody).get(FLOWISE_AUTHAPI_JSONKEY_MSG));
	    if (errorMessage.equals(FLOWISE_AUTHAPI_JSONVAL_MSG_USERNOTFOUND)) {
          // No more passwords will be tested for this user
	      this.cache_badUsernames.add( credential.username() );
	    }
	  }
    } catch (JsonSyntaxException e) {
	  return false;
    }
    return false;
  }

  public static JsonObject getJsonObject(String jsonStr) {
    Gson gson = new Gson();
    return gson.fromJson(jsonStr, JsonObject.class);
  }
  public static Set<String> getJsonKeys(String jsonStr) {
    Set<String> jsonKeys = new HashSet<>();
    for (Map.Entry<String, JsonElement> entry : FlowiseCredentialTester.getJsonObject(jsonStr).entrySet()) {
      jsonKeys.add(entry.getKey());
    }
    return jsonKeys;
  }
  public static String getJsonStr(JsonElement el) {
    if (el == null || el.isJsonNull()) {
      return null;
    }
    if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
      return el.getAsString(); // raw string
    }
    return el.toString(); // otherwise JSON representation
  }
  
  
  private static final class FlowiseValdationUtil {
    // Flowise authentication requires an email as a login, and the password to respect the password policy.
    // See functions isInvalidEmail() and isInvalidPassword() in https://github.com/FlowiseAI/Flowise/blob/main/packages/server/src/enterprise/utils/validation.util.ts
    private static Pattern RGX_EMAIL = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static Pattern RGX_PASSWORD = Pattern.compile(
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z0-9]).{8,}$");
        
    public static boolean isInvalidEmail(String email) {
      return (email.length() > 255 || !RGX_EMAIL.matcher(email).matches());
    }
    
    public static boolean isInvalidPassword(String password) {
      return (password.length() > 128 || !RGX_PASSWORD.matcher(password).matches());
    }
    
    public static String upgradeToValidEmail(String email) {
      // Appending domain, which in most cases creates a valid email
      String validEmail = email + FLOWISE_POLICY_EMAIL_APPEND_DOMAIN;
      // Checking again
      if (FlowiseValdationUtil.isInvalidEmail(validEmail)) {
        // logger.atWarning().log("Invalid email generated by FlowiseValdationUtil: " +validEmail);
        return "";
      }
      return validEmail;
    }
    
    public static String upgradeToValidPassword(String password) {
      String validPassword = password;
      // Password policy testing (password is not null)
      boolean hasDigit = password.chars().anyMatch(Character::isDigit);
      long nbLowercase = password.chars().filter(Character::isLowerCase).count();
      long nbUppercase = password.chars().filter(Character::isUpperCase).count();
      boolean hasSpecialChar = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));

      // Missing digit
      if (!hasDigit) {
        validPassword += FLOWISE_POLICY_PASSWORD_APPEND_DIGIT;
      }
      // Missing special character
      if (!hasSpecialChar) {
        validPassword += FLOWISE_POLICY_PASSWORD_APPEND_SPECIALCHAR;
      }
      
      // Missing uppercase. If possible, change the first letter to uppercase
      if (nbUppercase == 0 && nbLowercase >= 2) {
        char[] chars = validPassword.toCharArray();
        for (int i = 0; i < chars.length; i++) {
          if (Character.isLetter(chars[i])) {
            chars[i] = Character.toUpperCase(chars[i]);
            break;
          }
        }
        validPassword = new String(chars);
      }
      
      // Checking again (for instance, passwords < 8 chars or without letters won't pass)
      if (FlowiseValdationUtil.isInvalidPassword(validPassword)) {
        // logger.atWarning().log("Invalid password generated by FlowiseValdationUtil: " +validPassword);
        return "";
      }
      return validPassword;
    }
  }
  
  private static final class FlowiseHttpResponseUtil {
	private final HttpResponse delegate;
	
	public FlowiseHttpResponseUtil(HttpResponse delegate) {
        this.delegate = delegate;
    }
	public static FlowiseHttpResponseUtil from(HttpResponse delegate) {
        return new FlowiseHttpResponseUtil(delegate);
    }
	
    public String getBodyStr() {
      return Jsoup.parse(
          this.delegate.bodyString().orElse("")
       ).body().text();
    }
  
    public String getTitleStr() {
      return Jsoup.parse(
          this.delegate.bodyString().orElse("")
       ).title();
    }
  }
}

