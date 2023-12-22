package com.google.tsunami.plugins.detectors.rce.torchserve;

public class MockTorchServeRandomUtils extends TorchServeRandomUtils {
    public boolean validateHash(String hash, String randomValue) {
        return true;
    }
}
