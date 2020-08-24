package io.jolocom.nativeUtils;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

public class NativeUtilsModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  static { System.loadLibrary("keriox_wrapper"); }

  public NativeUtilsModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  private void rejectWithException(Promise promise, String code, Exception e) {
    String[] sp = e.getMessage().split(": ");
    String s = sp[sp.length - 1].trim().replace("\"", "");
    promise.reject(code, s);
  }

  @Override
  public String getName() {
    return "NativeUtils";
  }

  @ReactMethod
  public void validateEvents(String events, Promise promise) {
    try {
      String result = validateEventsStr(events);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "parsing the KEL", e);
    }
  }

  @ReactMethod
  public void extractIdFromEvent(String event, Promise promise) {
    try {
      String result = extractIdFromEventStr(event);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "extracting the ID from key event", e);
    }
  }

  @ReactMethod
  public void newWallet(String id, String pass, Promise promise) {
    try {
      String result = newWalletStr(id, pass);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "creating an empty wallet", e);
    }
  }

  @ReactMethod
  public void keriInceptWallet(String ew, String id, String pass,
                               Promise promise) {
    try {
      String result = keriInceptWalletStr(ew, id, pass);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "incepting a KERI identity with a wallet",
                          e);
    }
  }

  @ReactMethod
  public void changePass(String ew, String id, String oldPass,
                         String newPass, Promise promise) {
    try {
      String result = changePassStr(ew, id, oldPass, newPass);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "changing a wallet password", e);
    }
  }

  @ReactMethod
  public void changeId(String ew, String id, String newId, String pass,
                       Promise promise) {
    try {
      String result = changeIdStr(ew, id, newId, pass);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "changing a wallet ID", e);
    }
  }

  @ReactMethod
  public void newKey(String ew, String id, String pass, String keyType,
                     String controller, Promise promise) {
    try {
      String result = newKeyStr(ew, id, pass, keyType, controller != null ? controller : "");
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "adding a new key pair to a wallet", e);
    }
  }

  @ReactMethod
  public void addContent(String ew, String id, String pass, String content,
                         Promise promise) {
    try {
      String result = addContentStr(ew, id, pass, content);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "adding content to a wallet", e);
    }
  }

  @ReactMethod
  public void setKeyController(String ew, String id, String pass, String keyRef,
                               String controller, Promise promise) {
    try {
      String result = setKeyControllerStr(ew, id, pass, keyRef, controller);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "setting a public key controller", e);
    }
  }

  @ReactMethod
  public void getKey(String ew, String id, String pass, String keyRef, Promise promise) {
    try {
      String result = getKeyStr(ew, id, pass, keyRef);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "getting a public key", e);
    }
  }

  @ReactMethod
  public void getKeyByController(String ew, String id, String pass,
                                 String controller, Promise promise) {
    try {
      String result = getKeyByControllerStr(ew, id, pass, controller);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "getting a public key", e);
    }
  }

  @ReactMethod
  public void getKeys(String ew, String id, String pass, Promise promise) {
    try {
      String result = getKeysStr(ew, id, pass);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "getting public keys", e);
    }
  }

  @ReactMethod
  public void sign(String ew, String id, String pass, String controller,
                   String data, Promise promise) {
    try {
      String result = signStr(ew, id, pass, controller, data);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "signing a message", e);
    }
  }

  @ReactMethod
  public void verify(String key, String keyType, String data, String signature,
                     Promise promise) {
    try {
      String result = verifyStr(key, keyType, data, signature);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "verifying a signature", e);
    }
  }

  @ReactMethod
  public void encrypt(String key, String keyType, String data, String aad,
                      Promise promise) {
    try {
      String result = encryptStr(key, keyType, data, aad);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "encrypting a message", e);
    }
  }

  @ReactMethod
  public void decrypt(String ew, String id, String pass, String keyRef,
                      String data, String aad, Promise promise) {
    try {
      String result = decryptStr(ew, id, pass, keyRef, data, aad);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "decrypting a message", e);
    }
  }

  @ReactMethod
  public void getRandom(String ew, String id, String pass, Promise promise) {
    try {
      String result = getRandomStr(ew, id, pass);
      promise.resolve(result);
    } catch (Exception e) {
      rejectWithException(promise, "generating random bytes", e);
    }
  }

  private static native String validateEventsStr(String events);
  private static native String extractIdFromEventStr(String event);
  private static native String newWalletStr(String id, String pass);
  private static native String keriInceptWalletStr(String ew, String id,
                                                   String pass);
  private static native String changePassStr(String ew, String id,
                                             String oldPass, String newPass);
  private static native String changeIdStr(String ew, String id, String newId,
                                           String pass);
  private static native String newKeyStr(String ew, String id, String pass,
                                         String keyType, String controller);
  private static native String addContentStr(String ew, String id, String pass,
                                             String content);
  private static native String setKeyControllerStr(String ew, String id,
                                                   String pass, String keyRef,
                                                   String controller);
  private static native String getKeyStr(String ew, String id, String pass,
                                         String keyRef);
  private static native String getKeyByControllerStr(String ew, String id,
                                                     String pass,
                                                     String controller);
  private static native String getKeysStr(String ew, String id, String pass);
  private static native String signStr(String ew, String id, String pass,
                                       String controller, String data);
  private static native String verifyStr(String key, String keyType,
                                         String data, String signature);
  private static native String encryptStr(String key, String keyType,
                                          String data, String aad);
  private static native String decryptStr(String ew, String id, String pass,
                                          String keyRef, String data,
                                          String aad);
  private static native String getRandomStr(String ew, String id, String pass);
}
