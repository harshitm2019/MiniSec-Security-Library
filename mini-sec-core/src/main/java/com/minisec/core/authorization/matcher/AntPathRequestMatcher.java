package com.minisec.core.authorization.matcher;

public class AntPathRequestMatcher implements RequestMatcher {

    private final String pattern;
    private final String httpMethod;

    public AntPathRequestMatcher(String pattern) {
        this(pattern, null);
    }

    public AntPathRequestMatcher(String pattern, String httpMethod) {
        this.pattern = pattern;
        this.httpMethod = httpMethod;
    }



    @Override
    public boolean matches(String path, String method) {

        if (path == null || method == null) {
            return false;
        }

        if (httpMethod != null && !httpMethod.equalsIgnoreCase(method)) {
            return false;
        }

        return matchesPattern(pattern, path);

    }

    private boolean matchesPattern(String pattern, String path) {

        if (pattern.equals(path)) {
            return true;
        }

        if (pattern.endsWith("/**")) {

            String prefix = pattern.substring(0, pattern.length() - 3);

            return path.equals(prefix) || path.startsWith(prefix + "/");
        }

        if (pattern.endsWith("/*")) {

            String prefix = pattern.substring(0, pattern.length() - 2);

            if (!path.startsWith(prefix + "/")) {
                return false;
            }

            String remaining = path.substring(prefix.length() + 1);

            return !remaining.contains("/");
        }

        return false;
    }

    public String getPattern() {
        return pattern;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

}
