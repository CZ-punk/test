package com.cos.security1.jwt;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryAccountStore {
    private final ConcurrentHashMap<Long, String> accountStore = new ConcurrentHashMap<>();


    public void store(Long userId, String token) {
        accountStore.put(userId, token);
    }

    public String get(Long userId) {
        return accountStore.get(userId);
    }

    public void remove(Long userId) {
        accountStore.remove(userId);
    }

    public boolean isEmpty() {
        return accountStore.isEmpty();
    }

    public boolean containsKey(Long userId) {
        return accountStore.containsKey(userId);
    }

}