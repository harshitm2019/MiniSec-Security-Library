package com.minisec.core.authorization.matcher;

public interface RequestMatcher {

    boolean matches(String path, String method);

}
