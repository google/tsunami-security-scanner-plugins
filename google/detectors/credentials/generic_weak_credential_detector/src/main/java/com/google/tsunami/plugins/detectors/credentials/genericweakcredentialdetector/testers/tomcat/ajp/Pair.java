/*
 * libajp13 - Pair.java
 *
 * Copyright (c) 2017 Luca Carettoni - Doyensec LLC. 
 * Copyright (c) 2010 Espen Wiborg
 *
 * Licensed under the Apache License, Version 2.0
 */
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ajp13;

/**
 * Pair consisting of two elements; utility class used for headers and
 * attributes
 * <p>
 * Alternatively, you can use Apache Commons
 */
public class Pair<T, U>
{

    final T a;
    final U b;

    /**
     * Pair constructor
     *
     * @param a T Left element
     * @param b U Right element
     */
    public Pair(T a, U b)
    {
        this.a = a;
        this.b = b;
    }

    /**
     * Create a new Pair given the left and right elements
     *
     * @param <K> k Left element
     * @param <V> v Right element
     * @param k K Left element
     * @param v V Right element
     * @return Instance of Pair
     */
    public static <K, V> Pair<K, V> make(K k, V v)
    {
        return new Pair<>(k, v);
    }
}
