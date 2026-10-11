package com.minisec.core.context;

public class SecurityContextHolder {

    private static final ThreadLocal<SecurityContext> CONTEXT = new ThreadLocal<>();

    private SecurityContextHolder() {
    }

    public static SecurityContext getContext() {

        SecurityContext context = CONTEXT.get();

        if (context == null) {
            context = new SecurityContext();
            CONTEXT.set(context);
        }

        return context;
    }

    public static void clearContext() {
        CONTEXT.remove();
    }

}
