package com.google.tsunami.plugins.fingerprinters.web.common;

import com.google.common.collect.ImmutableSet;

public class WebConstant {
   public static final ImmutableSet<String> IGNORED_EXTENTIONS =
            ImmutableSet.of(
                    "php", "inc", "py", "rb", "pl", "java", "lua", "go", "asp", "aspx", "jsp", "cgi",
                    "sql", "png", "gif", "jpg", "jpeg", "swf", "mp4", "xml", "svg", "ico",
                    "ttf", "woff2"
            );
}
