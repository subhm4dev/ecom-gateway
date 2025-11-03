package com.ecom.gateway.util;

import org.springframework.util.AntPathMatcher;

import java.util.List;

/**
 * Utility for matching request paths against public path patterns
 */
public class PublicPathMatcher {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final List<String> publicPaths;

    public PublicPathMatcher(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    /**
     * Check if a path matches any public path pattern
     */
    public boolean isPublicPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        // Normalize path (remove query string, ensure starts with /)
        String normalizedPath = normalizePath(path);
        
        return publicPaths.stream()
            .anyMatch(pattern -> pathMatcher.match(pattern, normalizedPath));
    }

    private String normalizePath(String path) {
        // Remove query string
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) {
            path = path.substring(0, queryIndex);
        }
        
        // Ensure starts with /
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        
        return path;
    }
}

