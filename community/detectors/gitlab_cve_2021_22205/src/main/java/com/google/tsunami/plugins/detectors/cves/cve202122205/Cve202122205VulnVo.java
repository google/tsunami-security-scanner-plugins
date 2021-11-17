package com.google.tsunami.plugins.detectors.cves.cve202122205;

import java.io.Serializable;

public class Cve202122205VulnVo implements Serializable {

  private static final long serialVersionUID = -2504305583389462830L;

  private String CsrfToken;

  private String Cookie;

  public String getCsrfToken() {
    return CsrfToken;
  }

  public void setCsrfToken(String csrfToken) {
    CsrfToken = csrfToken;
  }

  public String getCookie() {
    return Cookie;
  }

  public void setCookie(String cookie) {
    Cookie = cookie;
  }
}
