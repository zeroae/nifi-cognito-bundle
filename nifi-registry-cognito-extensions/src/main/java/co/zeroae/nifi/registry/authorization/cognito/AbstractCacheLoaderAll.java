package co.zeroae.nifi.registry.authorization.cognito;

import com.github.benmanes.caffeine.cache.CacheLoader;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

abstract class AbstractCacheLoaderAll<K, V> implements CacheLoader<K, Optional<V>> {
    @Override
    public @NonNull Map<@NonNull K, @NonNull Optional<V>> loadAll(@NonNull Iterable<? extends @NonNull K> keys) {
        Map<K, Optional<V>> rv = new HashMap<>();
        Set<V> allValues = getAllValues();
        allValues.forEach(v -> rv.put(getKey(v), Optional.ofNullable(v)));
        keys.forEach(key -> {
            if (!rv.containsKey(key))
                rv.put(key, Optional.empty());
        });
        return rv;
    }

    public abstract Set<V> getAllValues();

    public abstract K getKey(V value);
}
