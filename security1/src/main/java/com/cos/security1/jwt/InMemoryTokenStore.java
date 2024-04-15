package com.cos.security1.jwt;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryTokenStore {
    private ConcurrentHashMap<String, String> tokenStore = new ConcurrentHashMap<>();

    public void storeToken(String key, String token) {
        tokenStore.put(key, token);
    }

    public String getToken(String key) {
        return tokenStore.get(key);
    }

    public void removeToken(String key) {
        tokenStore.remove(key);
    }
}