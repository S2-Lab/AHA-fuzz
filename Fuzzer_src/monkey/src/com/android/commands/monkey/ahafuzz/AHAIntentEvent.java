package com.android.commands.monkey.ahafuzz;

import android.app.ActivityManager;
import android.app.IActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.IPackageManager;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.view.IWindowManager;
import com.android.commands.monkey.MonkeyEvent;
import com.android.commands.monkey.Mutation;
import com.android.commands.monkey.ape.utils.Logger;
import com.android.commands.monkey.arguments.CustomFeedbackMap;
import com.android.commands.monkey.arguments.StringHintList;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.*;
import org.json.*;
import org.w3c.dom.*;

/**
 * AHAFuzz intent event for BPF feedback-based fuzzing.
 * Handles intent generation, mutation, and injection to target applications.
 */
public class AHAIntentEvent extends MonkeyEvent {

  private List<ComponentName> mMainApps;
  JSONObject intent_data;
  static String package_name;
  static String ExplicitClassname;
  static StringHintList string_hint_list = new StringHintList();
  static CustomFeedbackMap custom_feedback_map = new CustomFeedbackMap();
  String ComponentType;
  String IntentCategory;
  static String pattern = "^[^a-zA-Z0-9]+";
  static Pattern compiledPattern;
  static File intentLogFile;
  static String intentLogFilePath = "/data/local/tmp/intentLog.txt";
  private static Boolean isFirstExecute = true;

  public AHAIntentEvent(JSONObject data, List<ComponentName> MainApps) {
    super(EVENT_BPF);
    intent_data = data;
    mMainApps = MainApps;
    intentLogFile = new File(intentLogFilePath);

    if (isFirstExecute) {
      Logger.BPFprintln(" Initializing AHAIntentEvent (first execution)");
      
      // Extract target package name from main applications
      if (!mMainApps.isEmpty()) {
        ComponentName firstComponent = mMainApps.get(0);
        String keyString = firstComponent.toString();
        int startIndex = keyString.indexOf("{") + 1;
        int endIndex = keyString.indexOf("/");
        package_name = keyString.substring(startIndex, endIndex);
        string_hint_list.addPackageName(package_name);
        Logger.BPFprintln(" Target package extracted: " + package_name);
        Logger.BPFprintln(" Main components: " + mMainApps.size() + " app(s)");
      } else {
        Logger.BPFprintln(
          "[AHAFuzz] WARNING: No main apps provided - will send intents to all applications"
        );
        package_name = "";
      }
      
      // Compile regex pattern for value-feedback processing
      compiledPattern = Pattern.compile(pattern);
      Logger.BPFprintln(" Regex pattern compiled: " + pattern);
      Logger.BPFprintln(" Intent log file: " + intentLogFilePath);
      isFirstExecute = false;
    }
    Logger.BPFprintln(" Mode: BPF feedback-guided fuzzing");
  }

  /**
   * Applies custom argument mutation based on feedback.
   * 
   * This method is called from getIntent() when processing symbol_table entries.
   * It maps eBPF-tracked method calls (like "getIntExtra") to their corresponding
   * data types and applies appropriate mutations.
   * 
   * @param intent The intent to modify
   * @param key The extra key name
   * @param value The method name from eBPF feedback (e.g., "getIntExtra")
   */
  public void getCustomArgument(Intent intent, String key, String value) {
    Logger.BPFprintln(" Processing custom argument: key=" + key + ", value=" + value);
    if (custom_feedback_map.checkExist(value)) {
      Logger.BPFprintln(" Custom feedback mapping found for: " + value);
      String targetType = custom_feedback_map.getValue(value);
      Logger.BPFprintln(" Applying mutation with target type: " + targetType);
      Mutation.mutateCustom(intent, key, targetType);
      Logger.BPFprintln(" Custom mutation applied successfully");
    } else {
      Logger.BPFprintln(
        "[AHAFuzz] WARNING: No custom feedback mapping found for key=" + key + ", value=" + value
      );
    }
  }

  /**
   * @return Intent for the new activity
   */
  private Intent getIntent() {
    try {
      Logger.BPFprintln(" ===== Intent Generation Started =====");
      Logger.BPFprintln(" Target package: " + package_name);
      
      // Parse BPF feedback data
      String intent_action = (String) intent_data.get("action");
      Logger.BPFprintln(" Step 1: Parsing action - " + intent_action);
      
      int mutation_score = (int) intent_data.get("discover_new");
      Logger.BPFprintln(" Step 2: Mutation score (discover_new) = " + mutation_score);
      
      JSONObject symbol_table = (JSONObject) intent_data.get("symbol_table");
      Logger.BPFprintln(" Step 3: Symbol table parsed (size: " + 
        (symbol_table != null ? symbol_table.length() : 0) + ")");
      
      JSONObject hint_table = (JSONObject) intent_data.get("hint_table");
      Logger.BPFprintln(" Step 4: Hint table parsed (size: " + 
        (hint_table != null ? hint_table.length() : 0) + ")");
      
      // Create base intent
      Intent intent = new Intent(intent_action);
      Logger.BPFprintln(" Step 5: Base intent created with action: " + intent_action);
      
      intent.setPackage(package_name); // Set target Application
      Logger.BPFprintln(" Step 6: Target package set to: " + package_name);

      // Determine intent category and component
      if (intent_action.contains("Explicit_Intent")) {
        ExplicitClassname = (String) intent_data.get("name");
        Mutation.initMutationMap(ExplicitClassname, package_name);
        intent.setComponent(new ComponentName(package_name, ExplicitClassname));
        IntentCategory = "Explicit";
        intent.setAction(ExplicitClassname);
        intent_action = ExplicitClassname;
        Logger.BPFprintln(" Step 7: Explicit intent configured - class: " + ExplicitClassname);
      } else {
        Mutation.initMutationMap(intent_action, package_name);
        IntentCategory = "Implicit";
        Logger.BPFprintln(" Step 7: Implicit intent configured");
      }
      
      ComponentType = (String) intent_data.get("component");
      Logger.BPFprintln(" Step 8: Component type: " + ComponentType);
      
      if (ComponentType.contains("activity")) {
        ExplicitClassname = (String) intent_data.get("name");
        intent.setComponent(new ComponentName(package_name, ExplicitClassname));
        Logger.BPFprintln(" Activity component set: " + ExplicitClassname);
      }
      
      intent.putExtra("AHAFuzz", "CCS25");
      Logger.BPFprintln(" Step 9: AHAFuzz marker added to intent");
      
      // Process hint table for value-feedback guided mutation
      if (!hint_table.toString().equals("{}")) {
        Logger.BPFprintln(" Step 10: Processing hint table (" + hint_table.length() + " entries)");
        int candidateCount = 0;
        int confirmedCount = 0;
        
        for (String key : hint_table.keySet()) {
          Matcher matcher = compiledPattern.matcher(key);
          String result;
          if (matcher.find()) {
            // Remove special characters from value-feedback key
            String specialCharPart = matcher.group();
            result = key.substring(specialCharPart.length());
            Logger.BPFprintln("   Cleaned key: '" + key + "' -> '" + result + "'");
          } else {
            result = key;
          }
          
          int isCandidate = (int) hint_table.get(key);
          
          if (isCandidate == 1) {
            // Confirmed mutation target
            Mutation.addMutationMap(intent_action, result);
            confirmedCount++;
            Logger.BPFprintln("   Added CONFIRMED mutation target: " + result);
          } else {
            // Candidate mutation target
            Mutation.addMutationCandidateMap(intent_action, result);
            candidateCount++;
            Logger.BPFprintln("   Added CANDIDATE mutation target: " + result);
          }
        }
        Logger.BPFprintln(" Hint table processing complete: " + confirmedCount + " confirmed, " + candidateCount + " candidates");
      } else {
        Logger.BPFprintln(" Step 10: Hint table is empty, skipping");
      }

      // Process symbol table for custom intents
      if (!symbol_table.toString().equals("{}")) {
        Logger.BPFprintln(" Step 11: Processing symbol table (custom intent) - " + symbol_table.length() + " entries");
        for (String key : symbol_table.keySet()) {
          String value = (String) symbol_table.get(key);
          Logger.BPFprintln("   Processing symbol: " + key + " = " + value);
          getCustomArgument(intent, key, value);
        }
        Logger.BPFprintln(" Symbol table processing complete");
      } else {
        Logger.BPFprintln(" Step 11: Symbol table is empty, no custom arguments");
      }

      Logger.BPFprintln(" ===== Intent Generation Completed Successfully =====");
      Logger.BPFprintln(" Final intent URI: " + intent.toUri(0));

      return intent;
    } catch (JSONException e) {
      Logger.err.println("[AHAFuzz] ERROR: Failed to parse JSON intent data");
      Logger.err.println("[AHAFuzz] Exception: " + e.getMessage());
      e.printStackTrace();
      return null;
    }
  }


  @Override
  public int injectEvent(
    IWindowManager iwm,
    IActivityManager iam,
    int verbose
  ) {
    Logger.BPFprintln(" ===== Intent Injection Started =====");
    
    Intent intent = getIntent();
    
    // Log intent to file
    try (
      BufferedWriter writer = new BufferedWriter(
        new FileWriter(intentLogFile, true)
      )
    ) {
      writer.write(intent.toUri(0));
      writer.newLine();
      Logger.BPFprintln(" Intent logged to file: " + intentLogFilePath);
    } catch (IOException e) {
      Logger.err.println("[AHAFuzz] WARNING: Failed to log intent to file");
      e.printStackTrace();
    }

    // Inject intent based on component type
    try {
      if (ComponentType.contains("Broadcast")) {
        Logger.BPFprintln(" >>> Injecting BroadcastReceiver intent <<<");
        Logger.BPFprintln(" Intent URI: " + intent.toUri(0));
        Logger.BPFprintln(" Target: " + package_name);
        
        iam.broadcastIntentWithFeature(
          null,
          null,
          intent,
          null,
          null,
          0,
          null,
          null,
          null,
          null,
          null,
          0,
          null,
          false,
          false,
          ActivityManager.getCurrentUser()
        );
        Logger.BPFprintln(" Broadcast intent sent successfully");
        
      } else if (ComponentType.contains("Service")) {
        Logger.BPFprintln(" >>> Injecting Service intent <<<");
        Logger.BPFprintln(" Intent URI: " + intent.toUri(0));
        Logger.BPFprintln(" Target package: " + package_name);
        
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        iam.startService(
          null,
          intent,
          null,
          false,
          package_name,
          null,
          ActivityManager.getCurrentUser()
        );
        Logger.BPFprintln(" Service intent sent successfully");
        
      } else {
        Logger.BPFprintln(" >>> Injecting Activity intent <<<");
        Logger.BPFprintln(" Intent URI: " + intent.toUri(0));
        Logger.BPFprintln(" Target package: " + package_name);
        
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        iam.startActivityAsUserWithFeature(
          null,
          package_name,
          null,
          intent,
          null,
          null,
          null,
          0,
          0,
          null,
          null,
          ActivityManager.getCurrentUser()
        );
        Logger.BPFprintln(" Activity intent sent successfully");
      }
      
      Logger.BPFprintln(" ===== Intent Injection Completed Successfully =====");
      return MonkeyEvent.INJECT_SUCCESS;
      
    } catch (RemoteException e) {
      Logger.err.println("[AHAFuzz] ERROR: Remote exception while sending intent");
      Logger.err.println("[AHAFuzz] Intent: " + intent.toUri(0));
      Logger.err.println("[AHAFuzz] Exception: " + e.getMessage());
      e.printStackTrace();
      return MonkeyEvent.INJECT_ERROR_REMOTE_EXCEPTION;
      
    } catch (SecurityException e) {
      Logger.err.println("[AHAFuzz] ERROR: Security exception (permissions error)");
      Logger.err.println("[AHAFuzz] Intent: " + intent.toUri(0));
      Logger.err.println("[AHAFuzz] This may indicate missing permissions");
      e.printStackTrace();
      return MonkeyEvent.INJECT_ERROR_SECURITY_EXCEPTION;
    }
  }
}

