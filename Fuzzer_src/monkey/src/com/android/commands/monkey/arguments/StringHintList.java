package com.android.commands.monkey.arguments;

import com.android.commands.monkey.Mutation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

/**
 * AHAFuzz: String hint list for intent fuzzing.
 * 
 * Provides commonly observed string values for mutation.
 * Used by AHAIntentEvent to store package name.
 */
public class StringHintList {

  public static final ArrayList<String> string_hint_list = new ArrayList<>();

  public static String packageName = "";

  public static String returnRandStr() {
    return string_hint_list.get(Mutation.mutateInt(string_hint_list.size()));
  }

  public static String returnPackageName() {
    return packageName;
  }

  public static void addPackageName(String packagename) {
    packageName = packagename;
  }
}

