package com.android.commands.monkey;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Binder;
import com.android.commands.monkey.TelephonyMutation;
import com.android.commands.monkey.MonkeyUtils.PackageFilter;
import com.android.commands.monkey.ape.utils.Logger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

/**
 * AHAFuzz: Mutate primitive values for intent fuzzing
 * 
 * Implements AFL++-inspired mutation strategies for:
 * - Primitive types (int, long, float, double, byte, char, short, boolean)
 * - Arrays of primitive types
 * - Strings (with corpus-based selection)
 * - Custom intent extras
 */

public class Mutation {

  public static Random random = new Random();
  public static HashMap<String, ArrayList<String>> MutationMap = new HashMap<>();
  public static HashMap<String, HashMap<String, HashSet<String>>> MutationCandidateMap = new HashMap<>();
  public static HashMap<String, HashMap<String, java.lang.Object>> prevMutationMap = new HashMap<>();
  
  private static final int[] INTERESTING_VALUES = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127,
    128, 255, 256, 512, 1024, 4096,
    32767, 32768, 65535, 65536,
    Integer.MAX_VALUE, Integer.MIN_VALUE
  };
  // Interesting value substitution
  public static int interestingValue() {
    int index = random.nextInt(INTERESTING_VALUES.length);
    return INTERESTING_VALUES[index];
  }

  // Bit flip mutation
  public static int bitFlip(int value) {
    Random random = new Random();
    int bit = random.nextInt(32); // select one from 0~31
    return value ^ (1 << bit);
  }
  // Arithmetic mutation (+/- small deltas)
  public static int arithmeticMutate(int value) {
    Random random = new Random();
    int delta = 1 + random.nextInt(35); // select one from 1 ~ 35
    boolean add = random.nextBoolean(); // true for +, false for -
    return add ? value + delta : value - delta;
  }
  // Endian-aware byte swap
  public static int byteSwap(int value) {
    return Integer.reverseBytes(value);
  }

  public static int mutateInt() {
    if (random.nextBoolean()) { // 50% probability
      return interestingValue();
    }
    return random.nextInt();
  }
  
  public static int mutateInt_VerySmall() {
    return random.nextInt(10);
  }

  public static int mutateInt(int val) {
    int choice = random.nextInt(4); // randomly select 0, 1, 2, or 3
    switch (choice) {
      case 0:
        return interestingValue();
      case 1:
        return bitFlip(val);
      case 2:
        return arithmeticMutate(val);
      case 3:
        return byteSwap(val);
      default:
        return random.nextInt(); // default value
    }
  }



//////////////////////////////////////////////////////////////////
  private static final long[] L_INTERESTING_VALUES = {
    -128L, -1L, 0L, 1L, 16L, 32L, 64L, 100L, 127L,
    128L, 255L, 256L, 512L, 1024L, 4096L,
    32767L, 32768L, 65535L, 65536L,
    Integer.MAX_VALUE, Integer.MIN_VALUE,
    Long.MAX_VALUE, Long.MIN_VALUE
  };

  public static long L_interestingValue() {
    int index = random.nextInt(L_INTERESTING_VALUES.length);
    return L_INTERESTING_VALUES[index];
  }

  public static long bitFlip(long value) {
    int bit = random.nextInt(64);
    return value ^ (1L << bit);
  }

  public static long arithmeticMutate(long value) {
    long delta = 1 + random.nextInt(35);
    return random.nextBoolean() ? value + delta : value - delta;
  }

  public static long byteSwap(long value) {
    return Long.reverseBytes(value);
  }

  public static long mutateLong() {
    if (random.nextBoolean()) { // 50% probability
      return L_interestingValue();
    }
    return random.nextLong();
  }
  
  public static long mutateLong(long val) {
    int choice = random.nextInt(4); // randomly select 0, 1, 2, or 3
    switch (choice) {
      case 0:
        return L_interestingValue();
      case 1:
        return bitFlip(val);
      case 2:
        return arithmeticMutate(val);
      case 3:
        return byteSwap(val);
      default:
        return random.nextLong(); // default value
    }
  }


//////////////////////////////////////////////////////////////////

  private static final short[] S_INTERESTING_VALUES = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127,
    (short) 128, (short) 255, (short) 256,
    (short) 32767, (short) 32768, (short) 65535
  };

  public static short S_interestingValue() {
    int index = random.nextInt(S_INTERESTING_VALUES.length);
    return S_INTERESTING_VALUES[index];
  }

  public static short bitFlip(short value) {
    int bit = random.nextInt(16);
    return (short) (value ^ (1 << bit));
  }

  public static short arithmeticMutate(short value) {
    int delta = 1 + random.nextInt(5); // small delta considering short range
    return (short) (random.nextBoolean() ? value + delta : value - delta);
  }

  public static short byteSwap(short value) {
    return Short.reverseBytes(value);
  }


  public static short mutateShort() {
    return S_interestingValue();
  }
  
  public static short mutateShort(short val) {
    int choice = random.nextInt(3); // randomly select 0, 1, or 2
    switch (choice) {
      case 0:
        return S_interestingValue();
      case 1:
        return bitFlip(val);
      case 2:
        return arithmeticMutate(val);
      default:
        return byteSwap(val);
    }
  }



//////////////////////////////////////////////////////////////////

  private static final int[] F_INTERESTING_VALUES = {
    0x00000000, // +0.0f
    0x80000000, // -0.0f
    0x3f800000, // 1.0f
    0xbf800000, // -1.0f
    0x7f800000, // +Infinity
    0xff800000, // -Infinity
    0x7fc00000  // NaN
  };

  public static float F_interestingValue() {
    int index = random.nextInt(F_INTERESTING_VALUES.length);
    return Float.intBitsToFloat(F_INTERESTING_VALUES[index]);
  }

  public static float bitFlip(float value) {
    int bits = Float.floatToIntBits(value);
    int bit = random.nextInt(32);
    bits ^= (1 << bit);
    return Float.intBitsToFloat(bits);
  }

  public static float arithmeticMutate(float value) {
    float delta = random.nextFloat() * 10f; // ±[0.0, 10.0)
    return random.nextBoolean() ? value + delta : value - delta;
  }

  public static float byteSwap(float value) {
    int bits = Float.floatToIntBits(value);
    int swapped = Integer.reverseBytes(bits);
    return Float.intBitsToFloat(swapped);
  }

  public static float mutateFloat() {
    if (random.nextBoolean()) { // 50% probability
      return L_interestingValue();
    }
    return random.nextLong();
  }
  
  public static float mutateFloat(float val) {
    int choice = random.nextInt(4); // randomly select 0, 1, 2, or 3
    switch (choice) {
      case 0:
        return L_interestingValue();
      case 1:
        return bitFlip(val);
      case 2:
        return arithmeticMutate(val);
      case 3:
        return byteSwap(val);
      default:
        return random.nextLong(); // default value
    }
  }


//////////////////////////////////////////////////////////////////

public static boolean mutateBool() {
  return random.nextBoolean();
}

//////////////////////////////////////////////////////////////////

  private static final byte[] B_INTERESTING_VALUES = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127
  };

  public static byte B_interestingValue() {
    int index = random.nextInt(B_INTERESTING_VALUES.length);
    return B_INTERESTING_VALUES[index];
  }

  public static byte bitFlip(byte value) {
    int bit = random.nextInt(8); // byte is 8 bits
    return (byte) (value ^ (1 << bit));
  }

  public static byte arithmeticMutate(byte value) {
    int delta = 1 + random.nextInt(5); // small delta
    return (byte) (random.nextBoolean() ? value + delta : value - delta);
  }

  public static byte mutateByte() {
    return B_interestingValue();
  }
  
  public static byte mutateByte(byte val) {
    int choice = random.nextInt(3); // randomly select 0, 1, or 2
    switch (choice) {
      case 0:
        return B_interestingValue();
      case 1:
        return bitFlip(val);
      default :
        return arithmeticMutate(val);
    }
  }

//////////////////////////////////////////////////////////////////

  private static final char[] C_INTERESTING_VALUES = {
    0x0000, 0x0001, 0x007F, 0x00FF, 0x7FFF, 0xFFFF
  };

  public static char C_interestingValue() {
    int index = random.nextInt(C_INTERESTING_VALUES.length);
    return C_INTERESTING_VALUES[index];
  }

  public static char bitFlip(char value) {
    int bit = random.nextInt(16);
    return (char) (value ^ (1 << bit));
  }

  public static char arithmeticMutate(char value) {
    int delta = 1 + random.nextInt(10);
    return (char) (random.nextBoolean() ? value + delta : value - delta);
  }

  public static char byteSwap(char value) {
    return Character.reverseBytes(value); // Java 1.7+
  }

  public static char mutateChar() {
    return C_interestingValue();
  }
  
  public static char mutateChar(char val) {
    int choice = random.nextInt(3); // randomly select 0, 1, or 2
    switch (choice) {
      case 0:
        return C_interestingValue();
      case 1:
        return bitFlip(val);
      case 2:
        return arithmeticMutate(val);
      default:
        return byteSwap(val);
    }
  }
//////////////////////////////////////////////////////////////////

  private static final long[] D_INTERESTING_VALUES = {
    0x0000000000000000L, // +0.0
    0x8000000000000000L, // -0.0
    0x3ff0000000000000L, // 1.0
    0xbff0000000000000L, // -1.0
    0x7ff0000000000000L, // +Infinity
    0xfff0000000000000L, // -Infinity
    0x7ff8000000000000L  // NaN
  };

  public static double D_interestingValue() {
    int index = random.nextInt(D_INTERESTING_VALUES.length);
    return Double.longBitsToDouble(D_INTERESTING_VALUES[index]);
  }

  public static double bitFlip(double value) {
    long bits = Double.doubleToLongBits(value);
    int bit = random.nextInt(64);
    bits ^= (1L << bit);
    return Double.longBitsToDouble(bits);
  }

  public static double arithmeticMutate(double value) {
    double delta = random.nextDouble() * 100.0;
    return random.nextBoolean() ? value + delta : value - delta;
  }

  public static double byteSwap(double value) {
    long bits = Double.doubleToLongBits(value);
    long swapped = Long.reverseBytes(bits);
    return Double.longBitsToDouble(swapped);
  }

  public static double mutateDouble() {
    if (random.nextBoolean()) { // 50% probability
      return D_interestingValue();
    }
    return random.nextDouble();
  }
  
  public static double mutateDouble(double val) {
    int choice = random.nextInt(4); // randomly select 0, 1, 2, or 3
    switch (choice) {
      case 0:
        return D_interestingValue();
      case 1:
        return bitFlip(val);
      case 2:
        return arithmeticMutate(val);
      case 3:
        return byteSwap(val);
      default:
        return random.nextDouble(); // default value
    }
  }

//////////////////////////////////////////////////////////////////





  public static <T> T mutateList(List<T> flag_list) {
    if (flag_list == null || flag_list.isEmpty()) {
      throw new IllegalArgumentException("List is Empty or Null.");
    }
    int randomIndex = random.nextInt(flag_list.size());
    return flag_list.get(randomIndex);
  }

  public static <T> T mutateArray(T[] array) {
    if (array == null || array.length == 0) {
      throw new IllegalArgumentException("Empty or Null.");
    }
    int randomIndex = random.nextInt(array.length);
    return array[randomIndex];
  }

  public static <T> T mutateArray(ArrayList<T> list) {
    if (list == null || list.isEmpty()) {
      throw new IllegalArgumentException("Empty or Null.");
    }
    int randomIndex = random.nextInt(list.size());
    return list.get(randomIndex);
  }

  public static int mutateArray(int[] array) {
    if (array == null || array.length == 0) {
      throw new IllegalArgumentException("Empty or Null.");
    }
    int randomIndex = random.nextInt(array.length);
    return array[randomIndex];
  }

  public static String mutateArray(String[] array) {
    if (array == null || array.length == 0) {
      throw new IllegalArgumentException("Empty or Null.");
    }
    int randomIndex = random.nextInt(array.length);
    return array[randomIndex];
  }

  public static boolean[] mutateArrays(boolean[] array) {
    if (array == null || array.length == 0) {
      throw new IllegalArgumentException("Empty or Null.");
    }
    for (int i = 0; i < array.length; i++) {
      array[i] = mutateBool();
    }
    return array;
  }

  public static String getRandomType() {
    int choice = random.nextInt(3); // randomly select 0, 1, or 2

    switch (choice) {
      case 0:
        return "boolean";
      case 1:
        return "int";
      case 2:
        return "String";
      default:
        return "long"; // default value
    }
  }

  public static void mutateCustom(
    Intent intent,
    String key,
    String targetType
  ) {

    Logger.BPFprintln(" Custom mutation started - key: " + key + ", targetType: " + targetType);
    
    String action = intent.getAction();
    HashMap<String, java.lang.Object> prevMutation = prevMutationMap.get(action);
    Logger.BPFprintln(" Retrieved previous mutation map for action: " + action);
    
    java.lang.Object prevValue = prevMutation.get(key);
    boolean firstExecute = false;

    if (prevValue == null) {
      firstExecute = true;
      Logger.BPFprintln(" First execution for key '" + key + "' - generating initial value");
    } else {
      Logger.BPFprintln(" Mutating existing value for key '" + key + "': " + prevValue);
    }

    Logger.BPFprintln(" Applying mutation for type: " + targetType);

    if (targetType == "boolean") {
      intent.putExtra(key, mutateBool());
    } else if (targetType == "boolean[]") {
      int targetSize = mutateInt_VerySmall();
      boolean[] mutationBase = new boolean[mutateInt_VerySmall()];
      for (int i = 0; i < targetSize; i++) {
        mutationBase[i] = mutateBool();
      }
      intent.putExtra(key, mutationBase);
    } else if (targetType == "int") {
      int mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateInt();
      } else {
        mutatedVal = mutateInt((Integer) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "int[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        int[] mutationBase = new int[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateInt();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        int[] prevList = (int[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateInt(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    } else if (targetType == "long") {
      long mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateLong();
      } else {
        mutatedVal = mutateLong((java.lang.Long) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "long[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        long[] mutationBase = new long[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateLong();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        long[] prevList = (long[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateLong(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    } else if (targetType == "short") {
      short mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateShort();
      } else {
        mutatedVal = mutateShort((java.lang.Short) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "short[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        short[] mutationBase = new short[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateShort();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        short[] prevList = (short[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateShort(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    } else if (targetType == "float") {
      float mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateFloat();
      } else {
        mutatedVal = mutateFloat((java.lang.Float) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "float[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        float[] mutationBase = new float[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateFloat();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        float[] prevList = (float[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateFloat(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    } else if (targetType == "byte") {
      byte mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateByte();
      } else {
        mutatedVal = mutateByte((java.lang.Byte) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "byte[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        byte[] mutationBase = new byte[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateByte();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        byte[] prevList = (byte[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateByte(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    } else if (targetType == "char") {
      char mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateChar();
      } else {
        mutatedVal = mutateChar((java.lang.Character) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "char[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        char[] mutationBase = new char[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateChar();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        char[] prevList = (char[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateChar(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    } else if (targetType == "double") {
      double mutatedVal;
      if (firstExecute) {
        mutatedVal = mutateDouble();
      } else {
        mutatedVal = mutateDouble((java.lang.Double) prevValue);
      }
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "double[]") {
      if (firstExecute) {
        int targetSize = mutateInt_VerySmall();
        double[] mutationBase = new double[mutateInt_VerySmall()];
        for (int i = 0; i < targetSize; i++) {
          mutationBase[i] = mutateDouble();
        }
        intent.putExtra(key, mutationBase);
        prevMutation.put(key, mutationBase);
      } else {
        double[] prevList = (double[]) prevValue;
        for (int i = 0; i < prevList.length; i++){
          prevList[i] = mutateDouble(prevList[i]);
        }
        intent.putExtra(key, prevList);
        prevMutation.put(key, prevList);
      }
    // java.lang.String
    } else if (targetType == "java.lang.String" || targetType == "java.lang.CharSequence") {
      String mutatedVal = getIntentRandomString(intent.getAction(), (String) prevValue);
      intent.putExtra(key, mutatedVal);
      prevMutation.put(key, mutatedVal);
    } else if (targetType == "java.lang.String[]" || targetType == "java.lang.CharSequence[]") {
      int targetSize = mutateInt_VerySmall();
      String[] mutationBase = new String[mutateInt_VerySmall()];
      for (int i = 0; i < targetSize; i++) {
        mutationBase[i] = getIntentRandomString(intent.getAction(), null);
      }
      intent.putExtra(key, mutationBase);
    // android.os.Bundle
    } else if (targetType == "android.os.Bundle") {
      Bundle bundle = new Bundle();
      intent.putExtra(key, bundle);
    // java.util.ArrayList
    } else if (targetType == "java.util.ArrayList") {
      ArrayList<java.lang.Object> list = new ArrayList<>();
      intent.putExtra(key, list);
    // android.os.IBinder
    } else if (targetType == "android.os.IBinder") {
      Binder binder = new Binder();
      intent.putExtra(key, binder);
    } else{
      if (mutateBool()){
        // consider telephony pdus
        byte[][] pdus = TelephonyMutation.MessageByteArray(intent.getAction());
        intent.putExtra(key, pdus);
      } else {
        String mutatedVal = getIntentRandomString(intent.getAction(), null);
        intent.putExtra(key, mutatedVal);
      }
    }
  }

  public static void initMutationMap(String action, String package_name) {
    if (!checkExist(action)) {
      ArrayList<String> newHintlist = new ArrayList<>();
      HashMap<String, HashSet<String>> newHintCandidatelist = new HashMap<>();
      HashMap<String, java.lang.Object> prevMutation = new HashMap<>();
      newHintlist.add(package_name);
      MutationMap.put(action, newHintlist);
      MutationCandidateMap.put(action, newHintCandidatelist);
      prevMutationMap.put(action, prevMutation);
    }
  }

  public static void addMutationMap(String action, String value) {
    MutationMap.get(action).add(value);
  }

  public static void addMutationCandidateMap(String action, String value) {
    String[] values = value.split("\\|Candidate\\|");
    String value1 = values[0];
    String value2 = values[1];

    HashMap<String, HashSet<String>> targetCandidateMaps = MutationCandidateMap.get(action);
    if (targetCandidateMaps.containsKey(value1)) {
      HashSet<String> candidates = targetCandidateMaps.get(value1);
      candidates.add(value2);
    } else {
      HashSet<String> candidates = new HashSet<>();
      candidates.add(value2);
      targetCandidateMaps.put(value1, candidates);
    }
    if (targetCandidateMaps.containsKey(value2)) {
      HashSet<String> candidates = targetCandidateMaps.get(value2);
      candidates.add(value1);
    } else {
      HashSet<String> candidates = new HashSet<>();
      candidates.add(value1);
      targetCandidateMaps.put(value2, candidates);
    }
  }

  public static Boolean checkExist(String action) {
    return MutationMap.containsKey(action);
  }

  public static Boolean checkExistValue(String action, String value) {
    return MutationMap.get(action).contains(value);
  }

  public static String getIntentRandomString(String action, String prev) {
    ArrayList<String> targetList = MutationMap.get(action);
    HashMap<String, HashSet<String>> targetCandidateList = MutationCandidateMap.get(action);
    if (prev != null) {
      if (targetCandidateList.containsKey(prev)) {
        String targetString = getRandomElement(targetCandidateList.get(prev));
        Logger.BPFprintln(" Candidate mutation found - action: " + action + ", prev: " + prev + ", target: " + targetString);
        return targetString;
      }
    }
    int randomIndex = random.nextInt(targetList.size());
    return targetList.get(randomIndex);
  }

  public static String getRandomElement(HashSet<String> set) {
    if (set.isEmpty()) {
        return null;
    }
    int targetIndex = random.nextInt(set.size());
    int currentIndex = 0;
    for (String element : set) {
        if (currentIndex == targetIndex) {
            return element;
        }
        currentIndex++;
    }
    return null; // this line should not be reached logically
}
}
// reference for creating types when adding feedback
// "getBooleanArrayExtra": "boolean[]",
// "getBundleExtra": "android.os.Bundle",
// "getByteArrayExtra": "byte[]",
// "getCharArrayExtra": "char[]",
// "getCharSequenceArrayExtra": "java.lang.CharSequence[]",
// "getCharSequenceArrayListExtra": "java.util.ArrayList",
// "getCharSequenceExtra": "java.lang.CharSequence",
// "getDoubleArrayExtra": "double[]",
// "getExtra": "java.lang.Object",
// "getFloatArrayExtra": "float[]",
// "getIBinderExtra": "android.os.IBinder",
// "getIntArrayExtra": "int[]",
// "getIntegerArrayListExtra": "java.util.ArrayList",
// "getLongArrayExtra": "long[]",
// "getParcelableArrayExtra": "android.os.Parcelable[]",
// "getParcelableArrayListExtra": "java.util.ArrayList",
// "getParcelableExtra": "android.os.Parcelable",
// "getSerializableExtra": "java.io.Serializable",
// "getShortArrayExtra": "short[]",
// "getStringArrayExtra": "java.lang.String[]",
// "getStringArrayListExtra": "java.util.ArrayList",
// "getStringExtra": "java.lang.String",
// "hasCategory": "boolean",
// "hasExtra": "boolean",
// "getBooleanExtra": "boolean",
// "getByteExtra": "byte",
// "getCharExtra": "char",
// "getDoubleExtra": "double",
// "getExtra": "java.lang.Object",
// "getFloatExtra": "float",
// "getIntExtra": "int",
// "getLongExtra": "long",
// "getParcelableArrayExtra": "java.lang.Object[]",
// "getParcelableArrayListExtra": "java.util.ArrayList",
// "getParcelableExtra": "java.lang.Object",
// "getSerializableExtra": "java.io.Serializable",
// "getShortExtra": "short",
