package com.android.commands.monkey.arguments;

import com.android.commands.monkey.Mutation;
import java.util.HashMap;
import java.util.HashSet;

/**
 * AHAFuzz: Maps eBPF-tracked Intent getter methods to their corresponding data types.
 * 
 * When eBPF observes calls like "getIntExtra", this map provides the type information
 * needed for intelligent mutation (e.g., "getIntExtra" -> "int").
 * 
 * Used by: AHAIntentEvent.getCustomArgument() for dynamic type-aware mutation.
 */
public class CustomFeedbackMap {

  public static final HashMap<String, String> customFeedback_map = new HashMap<>();

  static {
    initializecustomFeedback_map_0();
  }

  private static void initializecustomFeedback_map_0() {
    // Intent.get*Extra() methods
    addEntry("getBooleanArrayExtra", "boolean[]");
    addEntry("getBundleExtra", "android.os.Bundle");
    addEntry("getByteArrayExtra", "byte[]");
    addEntry("getCharArrayExtra", "char[]");
    addEntry("getCharSequenceArrayExtra", "java.lang.CharSequence[]");
    addEntry("getCharSequenceArrayListExtra", "java.util.ArrayList");
    addEntry("getCharSequenceExtra", "java.lang.CharSequence");
    addEntry("getDoubleArrayExtra", "double[]");
    addEntry("getFloatArrayExtra", "float[]");
    addEntry("getIBinderExtra", "android.os.IBinder");
    addEntry("getIntArrayExtra", "int[]");
    addEntry("getIntegerArrayListExtra", "java.util.ArrayList");
    addEntry("getLongArrayExtra", "long[]");
    addEntry("getShortArrayExtra", "short[]");
    addEntry("getStringArrayExtra", "java.lang.String[]");
    addEntry("getStringArrayListExtra", "java.util.ArrayList");
    addEntry("getStringExtra", "java.lang.String");
    addEntry("hasCategory", "boolean");
    addEntry("hasExtra", "boolean");
    addEntry("getBooleanExtra", "boolean");
    addEntry("getByteExtra", "byte");
    addEntry("getCharExtra", "char");
    addEntry("getDoubleExtra", "double");
    addEntry("getExtra", "java.lang.Object");
    addEntry("getFloatExtra", "float");
    addEntry("getIntExtra", "int");
    addEntry("getLongExtra", "long");
    addEntry("getParcelableArrayExtra", "java.lang.Object[]");
    addEntry("getParcelableArrayListExtra", "java.util.ArrayList");
    addEntry("getParcelableExtra", "java.lang.Object");
    addEntry("getSerializableExtra", "java.io.Serializable");
    addEntry("getShortExtra", "short");

    // Bundle.get*() methods
    addEntry("get", "java.lang.Object");
    addEntry("getArrayList", "java.util.ArrayList");
    addEntry("getBoolean", "boolean");
    addEntry("getBooleanArray", "boolean[]");
    addEntry("getByte", "byte");
    addEntry("getByteArray", "byte[]");
    addEntry("getChar", "char");
    addEntry("getCharArray", "char[]");
    addEntry("getCharSequence", "java.lang.CharSequence");
    addEntry("getCharSequenceArray", "java.lang.CharSequence[]");
    addEntry("getCharSequenceArrayList", "java.util.ArrayList");
    addEntry("getDouble", "double");
    addEntry("getDoubleArray", "double[]");
    addEntry("getFloat", "float");
    addEntry("getFloatArray", "float[]");
    addEntry("getInt", "int");
    addEntry("getIntArray", "int[]");
    addEntry("getIntegerArrayList", "java.util.ArrayList");
    addEntry("getLong", "long");
    addEntry("getLongArray", "long[]");
    addEntry("getSerializable", "java.io.Serializable");
    addEntry("getShort", "short");
    addEntry("getShortArray", "short[]");
    addEntry("getString", "java.lang.String");
    addEntry("getStringArray", "java.lang.String[]");
    addEntry("getStringArrayList", "java.util.ArrayList");
    addEntry("getValue", "java.lang.Object");
  }

  private static void addEntry(String key, String value) {
    customFeedback_map.put(key, value);
  }

  public static Boolean checkExist(String value) {
    return customFeedback_map.containsKey(value);
  }

  public static String getValue(String value) {
    return customFeedback_map.get(value);
  }
}

