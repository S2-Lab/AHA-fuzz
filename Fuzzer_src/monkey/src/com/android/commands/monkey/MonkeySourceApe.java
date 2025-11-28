/*
 * Copyright 2020 Advanced Software Technologies Lab at ETH Zurich, Switzerland
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

/*
 * 
 * ====================================================================================
 * AHAFuzz Modifications 
 * ====================================================================================
 * 
 * This file contains AHAFuzz intent fuzzing implementation integrated with APE.
 * 
 * NAVIGATION GUIDE - AHAFuzz Implementation Locations:
 * ======================================================
 * 
 * SECTION 1. FIELDS & CONSTANTS 
 *    - BPF_EventList, BPF_InfoList, BPF_BlackList
 *    - Intent metadata constants (CATEGORY, REGISTERED, COVERAGE, etc.)
 *    - Scheduling variables (GuiIntentEventRatio, eventCount, etc.)
 * 
 * SECTION 2. BPF FEEDBACK PROCESSING 
 *    - watchFile()              : File monitoring for BPF feedback
 *    - readUpdatedContent()     : Parse real-time BPF updates
 *    - readUpdatedContentInit() : Initial BPF feedback loading
 *    - mergeJsonObjects()       : JSON merging utility
 * 
 * SECTION 3. CONSTRUCTOR INITIALIZATION
 *    - BPF priority queue setup
 *    - Blacklist initialization
 *    - File watcher startup
 * 
 * SECTION 4. INTENT EVENT GENERATION
 *    - generateBPFEvent()       : Main BPF intent generation
 *    - printEventList()         : Debug output
 *    - checkBlackList()         : Intent filtering
 *    - generateBPFManifestEvent() : Manifest intent handling
 *    - reGenerateManifestIntent() : Re-queue manifest intents
 * 
 * SECTION 5. SCHEDULING LOGIC 
 *    - getNextEvent()           : GUI/Intent event scheduler (MAIN ENTRY POINT)
 *    - calculateProbability()   : Dynamic probability calculation
 * 
 * ====================================================================================
 */

package com.android.commands.monkey;

import static com.android.commands.monkey.ape.utils.Config.defaultGUIThrottle;
import static com.android.commands.monkey.ape.utils.Config.doFuzzing;
import static com.android.commands.monkey.ape.utils.Config.fuzzingRate;
import static com.android.commands.monkey.ape.utils.Config.imageWriterCount;
import static com.android.commands.monkey.ape.utils.Config.refectchInfoCount;
import static com.android.commands.monkey.ape.utils.Config.refectchInfoWaitingInterval;
import static com.android.commands.monkey.ape.utils.Config.swipeDuration;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.app.ActivityManager.RunningTaskInfo;
import android.app.UiAutomation;
import android.app.UiAutomationConnection;
import android.content.ComponentName;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.Rect;
import android.hardware.display.DisplayManagerGlobal;
import android.os.Build;
import android.os.FileObserver;
import android.os.HandlerThread;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.accessibility.AccessibilityNodeInfo;
import com.android.commands.monkey.ape.Agent;
import com.android.commands.monkey.ape.AndroidDevice;
import com.android.commands.monkey.ape.ImageWriterQueue;
import com.android.commands.monkey.ape.StopTestingException;
import com.android.commands.monkey.ape.agent.ApeAgent;
import com.android.commands.monkey.ape.agent.ReplayAgent;
import com.android.commands.monkey.ape.events.ApeEvent;
import com.android.commands.monkey.ape.model.Action;
import com.android.commands.monkey.ape.model.ActionType;
import com.android.commands.monkey.ape.model.FuzzAction;
import com.android.commands.monkey.ape.model.ModelAction;
import com.android.commands.monkey.ape.model.StartAction;
import com.android.commands.monkey.ape.tree.GUITreeNode;
import com.android.commands.monkey.ape.utils.Logger;
import com.android.commands.monkey.ape.utils.RandomHelper;
import com.android.commands.monkey.ahafuzz.AHAIntentEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchEvent.Kind;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.TimeoutException;
import org.json.*;

/**
 * monkey event queue
 */
public class MonkeySourceApe implements MonkeyEventSource {

  private static long CLICK_WAIT_TIME = 0L;
  private static long LONG_CLICK_WAIT_TIME = 1000L;

  private static final boolean useRandomClick = false;

  static KeyCharacterMap CharMap;

  static {
    if (Build.VERSION.SDK_INT >= 11) CharMap = // My soft runs until API 5
      KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD); else CharMap =
      KeyCharacterMap.load(KeyCharacterMap.ALPHA);
  }

  /** Possible screen rotation degrees **/
  private static final int[] SCREEN_ROTATION_DEGREES = {
    Surface.ROTATION_0,
    Surface.ROTATION_90,
    Surface.ROTATION_180,
    Surface.ROTATION_270,
  };

  private List<ComponentName> mMainApps;
  private Map<String, String[]> packagePermissions;
  private int mEventCount = 0; // total number of events generated so far
  private MonkeyEventQueue mQ;
  private int mVerbose = 0;
  // private long mThrottle = defaultGUIThrottle;
  private long mThrottle = defaultGUIThrottle * 2; // taint analysis mode
  private boolean mRandomizeThrottle = false;
  private MonkeyPermissionUtil mPermissionUtil;
  private Random mRandom;

  // private boolean mKeyboardOpen = false;
  private Agent mAgent;
  private int mEventId = 0;
  private int statusBarHeight = -1;
  private File mOutputDirectory;
  private PrintWriter mEventProduceLogger;
  private PrintWriter mEventConsumeLogger;
  private File mEventProduceLoggerFile;
  private File mEventConsumeLoggerFile;
  private ImageWriterQueue[] mImageWriters;

  // Counter

  int nullInfoCounter = 0;
  int lostFocusedCounter = 0;

  // ====================================================================================
  // BEGIN: AHAFuzz Implementation - eBPF Feedback & Intent Fuzzing
  // ====================================================================================
  // 
  // SECTION 1 : FIELDS & CONSTANTS 
  // 
  // This section contains AHAFuzz-specific fields and data structures for:
  // - eBPF feedback processing from BPF programs
  // - Intent event priority queue management
  // - Coverage tracking and scoring
  // - GUI/Intent event ratio scheduling
  //
  // ====================================================================================
  
  PriorityQueue<JSONObject> BPF_EventList;
  PriorityQueue<JSONObject> BPF_ManifestEventList;
  static HashMap<String, List<Integer>> BPF_InfoList;
  static HashSet<String> BPF_BlackList;
  private static String JSON_Path = "/data/local/tmp/message/bpf_output.json";
  static String Blacklist_Path = "/data/local/tmp/BlackList.txt";
  static File BlackList;
  int lastReadLine;
  FileObserver observer;
  long lastReadPosition = 0;
  Boolean FirstTimeLoad = true;
  static String lastIUpdatedntent = "";
  static String lastIntentAction = "";
  static int lastIntentSymLen = 0;
  static int lastIntentHintLen = 0;
  static int manifestCount = 0;
  static int eventCount = 0;
  static double GuiIntentEventRatio = 0.5;
  static int ScoreBaseline = 0;
  static int GUIEventCnt = 1;
  static int IntentEventCnt = 1;
  static Boolean isIntentEvent = true;

  public static final int INFONUM = 7; // explicit or implicit
  public static final int CATEGORY = 0; // explicit or implicit
  public static final int REGISTERED = 1; // static(manifest) or dynamic
  public static final int COVERAGE = 2; // contains "discover_new" ->
  public static final int KEYNUM = 3; // length of key
  public static final int VALUENUM = 4; // length of value(hint table)
  public static final int COMPONENT = 5; // length of value(hint table)
  public static final int EXIST = 6; // is intent event in the priority queue
  // feedback only contains updated hint table -> if hint table's length is over 0, it means that hint table updated & coverage increased

  public static final int EXPLICIT = 0;
  public static final int IMPLICIT = 1;

  public static final int STATIC = 0;
  public static final int DYNAMIC = 1;

  public static final int BROADCAST = 0;
  public static final int SERVICE = 1;
  public static final int ACTIVITY = 2;

  public static final int EXISTING = 0;
  public static final int NONEXIST = 1;

  // Escape eternal waiting count
  int activityLoadingCount = 0;

  // ====================================================================================
  // AHAFuzz Methods - eBPF Feedback File Monitoring
  // ====================================================================================
  //
  // SECTION 2 : BPF FEEDBACK PROCESSING 
  //
  // These methods handle:
  // - File watching for BPF feedback updates
  // - Incremental reading of feedback JSON
  // - Intent metadata parsing and priority calculation
  // - Corpus management and merging
  //
  // ====================================================================================

  public void watchFile(String path) throws IOException {
    Thread watchThread = new Thread(() -> {
      try {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        Path filePath = Paths.get(path);
        filePath
          .getParent()
          .register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
        while (true) {
          WatchKey key;
          try {
            key = watchService.take();
          } catch (InterruptedException e) {
            return;
          }

          for (WatchEvent<?> event : key.pollEvents()) {
            if (
              event.kind() == StandardWatchEventKinds.ENTRY_MODIFY &&
              event
                .context()
                .toString()
                .equals(filePath.getFileName().toString())
            ) {
              readUpdatedContent(path);
            }
          }
          key.reset();
        }
      } catch (Exception e) {
        Logger.err.println("AHAFuzz Error: watchFile");
      }
    });
    watchThread.start();
  }

  public void readUpdatedContent(String path) {
    try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
      raf.seek(lastReadPosition);
      String line;
      while ((line = raf.readLine()) != null) {
        try {
          JSONObject jsonObject = new JSONObject(line);
          String IntentAction = (String) jsonObject.get("action");
          int IntentSymLen =
            ((JSONObject) jsonObject.get("symbol_table")).length();
          int IntentHintLen =
            ((JSONObject) jsonObject.get("hint_table")).length();
          if (
            (IntentAction.equals(lastIUpdatedntent)) &&
            (IntentSymLen == lastIntentSymLen) &&
            (IntentHintLen == lastIntentHintLen)
          ) {
            // Same feedback as last: lower priority but still add to queue
            Logger.BPFprintln(" Same BPF feedback for " + IntentAction + 
                             " - adding with reduced priority");
            
            // Check if already in queue (EXIST == EXISTING)
            if (BPF_InfoList.containsKey(IntentAction)) {
              List<Integer> IntentInfo = BPF_InfoList.get(IntentAction);
              
              if (IntentInfo.get(EXIST) == EXISTING) {
                // Already in queue and repeated feedback: apply penalty
                Logger.BPFprintln(" Duplication detected (EXIST==EXISTING), applying score penalty");
                int currentCoverage = IntentInfo.get(COVERAGE);
                if (currentCoverage > 0) {
                  IntentInfo.set(COVERAGE, currentCoverage - 2);  // Aggressive penalty
                }
                int penaltyScore = Math.max(currentCoverage - 2, -5);  // Minimum -5
                jsonObject.put("score", penaltyScore + ScoreBaseline);
                BPF_EventList.add(jsonObject);
                Logger.BPFprintln(" Added with penalty score: " + (penaltyScore + ScoreBaseline));
              } else {
                // EXIST == NONEXIST: intent was sent, add with moderate score
                Logger.BPFprintln(" Intent was sent (EXIST==NONEXIST), adding with moderate priority");
                IntentInfo.set(EXIST, EXISTING);
                int moderateScore = ScoreBaseline + 3;  // Lower than new coverage but not negative
                jsonObject.put("score", moderateScore);
                BPF_EventList.add(jsonObject);
                Logger.BPFprintln(" Added with moderate score: " + moderateScore);
              }
            } else {
              // New intent: add with default score
              jsonObject.put("score", ScoreBaseline + 5);
              BPF_EventList.add(jsonObject);
            }
            
            lastIUpdatedntent = IntentAction;
            lastIntentSymLen = IntentSymLen;
            lastIntentHintLen = IntentHintLen;
          } else {
              Logger.BPFprintln(" Feedback data: " + jsonObject.toString());
            }
            if (IntentAction.contains("GuiIntentScheduling")) {
              double ratio = ((double) jsonObject.get("count") / 100);
              if (ratio < (1 - GuiIntentEventRatio)) {
                GuiIntentEventRatio += 0.1;
                if (GuiIntentEventRatio >= 0.8) {
                  GuiIntentEventRatio = 0.8;
                }
              } else {
                reGenerateManifestIntent();
                GuiIntentEventRatio -= 0.1;
                if (GuiIntentEventRatio <= 0.2) {
                  GuiIntentEventRatio = 0.2;
                }
              }
              continue;
            }

            if (BPF_InfoList.containsKey(IntentAction)) {
              // already known intent
              List<Integer> IntentInfo = BPF_InfoList.get(IntentAction);
              int discover_new = (int) jsonObject.get("discover_new");
              if (IntentInfo.get(EXIST) == EXISTING) {
                Logger.BPFprintln(
                  "Skip " + IntentAction + " because of duplication"
                );
                continue;
              }

              // setting explicit/implicit
              if (IntentInfo.get(CATEGORY) == EXPLICIT) {
                jsonObject.put("action", "Explicit_Intent");
                jsonObject.put("name", IntentAction);
              }
              if (IntentInfo.get(COMPONENT) == BROADCAST) {
                jsonObject.put("component", "Broadcast");
              } else if (IntentInfo.get(COMPONENT) == SERVICE) {
                jsonObject.put("component", "Service");
              } else if (IntentInfo.get(COMPONENT) == ACTIVITY) {
                jsonObject.put("component", "activity");
              }

              // calculate score
              int score = 0;
              IntentInfo.set(KEYNUM, IntentSymLen);
              // 1. coverage :
              //   if coverage is updated(discover_new > 0), set COVERAGE to 5
              //   after iteration, if coverage is not updated, then discount COVERAGE
              //   this COVERAGE value directly used in calculating score
              if (discover_new > 0) {
                IntentInfo.set(COVERAGE, 7);
                score += 7;
              } else {
                int currentCoverage = IntentInfo.get(COVERAGE);
                if (currentCoverage > 0) {
                  IntentInfo.set(COVERAGE, currentCoverage - 1);
                }
                score += currentCoverage - 1;
              }
              // 2. Static/Dynamic :
              //   we have to focus dynamic intent more than static intent; because of lifetime
              if (IntentInfo.get(REGISTERED) == DYNAMIC) {
                score += 1;
              }
              // 3. key list :
              //   if intent require many key, we focus that intent
              if (IntentSymLen >= 5) {
                score += 2;
              } else if (IntentSymLen > 0) {
                score += 1;
              }
              // 4. value list :
              //  value list(hint list) exist only if value list is updated
              if (IntentHintLen > 0) {
                score += 5;
              }
              // 5. component information : 
              // We priorily test broadcast first, next service and finally activity
              if (IntentInfo.get(COMPONENT) == BROADCAST) {
                score += 3;
              } else if (IntentInfo.get(COMPONENT) == SERVICE) {
                score += 2;
              }
              if (IntentInfo.get(CATEGORY) != EXPLICIT) {
                score += 3;
              }

              IntentInfo.set(EXIST, EXISTING);
              jsonObject.put("score", score + ScoreBaseline);
            } else {
              // new intent : dynamically registered intent
              List<Integer> infoList = new ArrayList<>(
                Collections.nCopies(INFONUM, null)
              );
              infoList.set(CATEGORY, IMPLICIT);
              infoList.set(REGISTERED, DYNAMIC);
              infoList.set(COVERAGE, 0);
              infoList.set(KEYNUM, 0);
              infoList.set(VALUENUM, 0);
              infoList.set(COMPONENT, BROADCAST);
              infoList.set(EXIST, EXISTING);
              BPF_InfoList.put(IntentAction, infoList);
              int score = 10;
              jsonObject.put("component", "Broadcast");
              jsonObject.put("score", score + ScoreBaseline);
            }
            BPF_EventList.add(jsonObject);
            lastIUpdatedntent = IntentAction;
            lastIntentSymLen = IntentSymLen;
            lastIntentHintLen = IntentHintLen;
        } catch (JSONException e) {
          Logger.err.println(
            "AHAFuzz Failed : Error while reading json file" + e.getMessage()
          );
        }
      }
      lastReadPosition = raf.getFilePointer();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void readUpdatedContentInit(String path) {
    Logger.BPFprintln("readUpdatedContentInit() called, initialized AHAFuzz");
    try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
      raf.seek(lastReadPosition);
      String line;
      Map<String, JSONObject> mergedResults = new HashMap<>();
      while ((line = raf.readLine()) != null) {
        try {
          JSONObject jsonObject = new JSONObject(line);
          String intentFlag = (String) jsonObject.get("init");
          if (intentFlag.contains("manifest")) {
            int initial_score = 0;
            String IntentAction = (String) jsonObject.get("action");
            String ComponentType = (String) jsonObject.get("component");
            if (IntentAction.contains("Explicit_Intent")) {
              String Componentname = (String) jsonObject.get("name");
              List<Integer> infoList = new ArrayList<>(
                Collections.nCopies(INFONUM, null)
              );
              infoList.set(CATEGORY, EXPLICIT);
              infoList.set(REGISTERED, STATIC);
              infoList.set(COVERAGE, 0);
              infoList.set(KEYNUM, 0);
              infoList.set(VALUENUM, 0);
              infoList.set(EXIST, NONEXIST); // After processing dynamically registered intent, set EXISTING
              if (ComponentType.contains("receiver")) {
                jsonObject.put("component", "Broadcast");
                infoList.set(COMPONENT, BROADCAST);
                initial_score += 2;
              } else if (ComponentType.contains("service")) {
                jsonObject.put("component", "Service");
                infoList.set(COMPONENT, SERVICE);
                initial_score += 1;
              } else {
                jsonObject.put("component", "activity");
                infoList.set(COMPONENT, ACTIVITY);
              }
              BPF_InfoList.put(Componentname, infoList);
            } else {
              initial_score += 5;
              List<Integer> infoList = new ArrayList<>(
                Collections.nCopies(INFONUM, null)
              );
              infoList.set(CATEGORY, IMPLICIT);
              infoList.set(REGISTERED, STATIC);
              infoList.set(COVERAGE, 0);
              infoList.set(KEYNUM, 0);
              infoList.set(VALUENUM, 0);
              infoList.set(EXIST, NONEXIST); // After processing dynamically registered intent, set EXISTING
              if (ComponentType.contains("receiver")) {
                jsonObject.put("component", "Broadcast");
                infoList.set(COMPONENT, BROADCAST);
                initial_score += 2;
              } else if (ComponentType.contains("service")) {
                jsonObject.put("component", "Service");
                infoList.set(COMPONENT, SERVICE);
                initial_score += 1;
              } else if (ComponentType.contains("activity")) {
                jsonObject.put("component", "activity");
                infoList.set(COMPONENT, ACTIVITY);
              }
              BPF_InfoList.put(IntentAction, infoList);
            }
            jsonObject.put("score", initial_score + ScoreBaseline);
            BPF_ManifestEventList.add(jsonObject);
            Logger.BPFprintln(
              "[AHAFuzz] Manifest intent loaded: " + jsonObject.toString()
            );
          } else {
            String action = jsonObject.getString("action");
            JSONObject value1 = jsonObject.getJSONObject("symbol_table");
            JSONObject value2 = jsonObject.getJSONObject("hint_table");

            if (mergedResults.containsKey(action)) {
              JSONObject existing = mergedResults.get(action);
              mergeJsonObjects(existing.getJSONObject("symbol_table"), value1);
              mergeJsonObjects(existing.getJSONObject("hint_table"), value2);
            } else {
              JSONObject newValues = new JSONObject();
              newValues.put("symbol_table", value1);
              newValues.put("hint_table", value2);
              mergedResults.put(action, newValues);
            }
          }
        } catch (JSONException e) {
          Logger.err.println(
            "AHAFuzz Failed : Error while reading json file" + e.getMessage()
          );
        }
      }
      mergedResults.forEach((action, values) -> {
        try {
          JSONObject BPFEvent = mergedResults.get(action);
          BPFEvent.put("action", action);
          BPFEvent.put("init", "False");
          BPFEvent.put("discover_new", 0);
          BPFEvent.put("score", 10 + ScoreBaseline);
          if (BPF_InfoList.containsKey(action)) {
            // already exist
            List<Integer> IntentInfo = BPF_InfoList.get(action);
            // setting explicit/implicit
            if (IntentInfo.get(CATEGORY) == EXPLICIT) {
              BPFEvent.put("action", "Explicit_Intent");
              BPFEvent.put("name", action);
            }
            if (IntentInfo.get(COMPONENT) == BROADCAST) {
              BPFEvent.put("component", "Broadcast");
            } else if (IntentInfo.get(COMPONENT) == SERVICE) {
              BPFEvent.put("component", "Service");
            } else {
              BPFEvent.put("component", "activity");
            }
            IntentInfo.set(EXIST, EXISTING);
          } else {
            // dynamically registered intent
            BPFEvent.put("component", "Broadcast");
            List<Integer> infoList = new ArrayList<>(
              Collections.nCopies(INFONUM, null)
            );
            infoList.set(CATEGORY, IMPLICIT);
            infoList.set(REGISTERED, DYNAMIC);
            infoList.set(COVERAGE, 0);
            infoList.set(KEYNUM, 0);
            infoList.set(VALUENUM, 0);
            infoList.set(COMPONENT, BROADCAST);
            infoList.set(EXIST, EXISTING);
            BPF_InfoList.put(action, infoList);
          }
          BPF_EventList.add(BPFEvent);

          Logger.BPFprintln(" Initial BPF feedback loaded: " + BPFEvent.toString());
        } catch (JSONException e) {
          Logger.err.println(
            "AHAFuzz Failed : Error while reading json file in readUpdatedContentInit : " +
            e.getMessage()
          );
        }
      });

      Iterator<JSONObject> iterator = BPF_ManifestEventList.iterator();
      while (iterator.hasNext()) {
        try {
          JSONObject jsonObject = iterator.next();
          String intent_action = (String) jsonObject.get("action");
          List<Integer> intentinfo;
          if (intent_action.contains("Explicit_Intent")) {
            String ExplicitClassname = (String) jsonObject.get("name");
            intentinfo = BPF_InfoList.get(ExplicitClassname);
          } else {
            intentinfo = BPF_InfoList.get(intent_action);
          }
          if (intentinfo.get(EXIST) == NONEXIST) {
            intentinfo.set(EXIST, EXISTING);
            BPF_EventList.add(jsonObject);
          }
        } catch (JSONException e) {
          Logger.err.println(
            "AHAFuzz Failed : Error while reading json file in readUpdatedContentInit : " +
            e.getMessage()
          );
        }
      }
      lastReadPosition = raf.getFilePointer();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void mergeJsonObjects(JSONObject target, JSONObject source) {
    source
      .keySet()
      .forEach(key -> {
        try {
          if (!target.has(key)) {
            target.put(key, source.get(key));
          }
        } catch (Exception e) {
          Logger.err.println(
            "AHAFuzz Failed : Error while reading json file in mergeJsonObjects : " +
            e.getMessage()
          );
        }
      });
  }

  // ====================================================================================

  /**
   * UiAutomation client and connection
   */
  protected final HandlerThread mHandlerThread = new HandlerThread(
    "MonkeySourceApe"
  );
  protected UiAutomation mUiAutomation;

  public static String getKeyName(int keycode) {
    return KeyEvent.keyCodeToString(keycode);
  }

  /**
   * Looks up the keyCode from a given KEYCODE_NAME. NOTE: This may be an
   * expensive operation.
   *
   * @param keyName
   *            the name of the KEYCODE_VALUE to lookup.
   * @returns the intenger keyCode value, or KeyEvent.KEYCODE_UNKNOWN if not
   *          found
   */
  public static int getKeyCode(String keyName) {
    return KeyEvent.keyCodeFromString(keyName);
  }

  public static boolean hasKey(int key) {
    return KeyCharacterMap.deviceHasKey(key);
  }

  public int getStatusBarHeight() {
    if (this.statusBarHeight == -1) {
      Display display = DisplayManagerGlobal
        .getInstance()
        .getRealDisplay(Display.DEFAULT_DISPLAY);
      DisplayMetrics dm = new DisplayMetrics();
      display.getMetrics(dm);
      this.statusBarHeight = (int) (24 * dm.density);
    }
    return this.statusBarHeight;
  }

  /**
   * Connect to AccessibilityService
   */
  public void connect() {
    if (mHandlerThread.isAlive()) {
      throw new IllegalStateException("Already connected!");
    }
    mHandlerThread.start();
    mUiAutomation =
      new UiAutomation(
        mHandlerThread.getLooper(),
        new UiAutomationConnection()
      );
    mUiAutomation.connect();

    AccessibilityServiceInfo info = mUiAutomation.getServiceInfo();
    // Compress this node
    info.flags &= ~AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;

    mUiAutomation.setServiceInfo(info);

    mImageWriters = new ImageWriterQueue[imageWriterCount];
    for (int i = 0; i < 3; i++) {
      mImageWriters[i] = new ImageWriterQueue();
      Thread imageThread = new Thread(mImageWriters[i]);
      imageThread.start();
    }
  }

  public int getEventCount() {
    return mEventCount;
  }

  /**
   * Disconnect to AccessibilityService
   */
  public void disconnect() {
    if (!mHandlerThread.isAlive()) {
      throw new IllegalStateException("Already disconnected!");
    }
    mUiAutomation.disconnect();
    mHandlerThread.quit();
  }

  public void tearDown() {
    this.disconnect();
    this.mAgent.tearDown();
    for (ImageWriterQueue writer : mImageWriters) {
      writer.tearDown();
    }
    this.mEventProduceLogger.close();
    this.mEventConsumeLogger.close();
    File visOutput = new File(getOutputDirectory(), "sataTimeline.vis.js");
    ApeRRFormatter.toVisTimeline(mEventProduceLoggerFile, visOutput);
  }

  public MonkeySourceApe(
    Random random,
    List<ComponentName> MainApps,
    long throttle,
    boolean randomizeThrottle,
    boolean permissionTargetSystem,
    File outputDirectory
  ) {
    mRandom = random;
    mMainApps = MainApps;
    packagePermissions = new HashMap<>();
    for (ComponentName app : MainApps) {
      packagePermissions.put(
        app.getPackageName(),
        AndroidDevice.getGrantedPermissions(app.getPackageName())
      );
    }
    mThrottle = throttle;
    if (mThrottle == 0) {
      mThrottle = defaultGUIThrottle;
    }
    mRandomizeThrottle = randomizeThrottle;
    mQ = new MonkeyEventQueue(random, 0, false); // we manage throttle
    mPermissionUtil = new MonkeyPermissionUtil();
    mPermissionUtil.setTargetSystemPackages(permissionTargetSystem);
    // mPermissionUtil.populatePermissionsMapping();
    mOutputDirectory = outputDirectory;
    mEventProduceLoggerFile = new File(mOutputDirectory, "produce.log");
    mEventProduceLogger = openWriter(mEventProduceLoggerFile);
    mEventConsumeLoggerFile = new File(mOutputDirectory, "consume.log");
    mEventConsumeLogger = openWriter(mEventConsumeLoggerFile);

    // ====================================================================================
    // AHAFuzz: BPF Feedback Manager Initialization
    // ====================================================================================
    // 
    // SECTION 3 : CONSTRUCTOR INITIALIZATION
    //
    // Initialize data structures for eBPF feedback processing and intent fuzzing:
    // - Priority queue setup with scoring comparator
    // - Blacklist loading from file
    // - File watcher initialization
    // ====================================================================================
    
    Comparator<JSONObject> comparator = new Comparator<>() {
      @Override
      public int compare(JSONObject o1, JSONObject o2) {
        try {
          return o2.getInt("score") - o1.getInt("score");
        } catch (JSONException e) {
          e.printStackTrace();
          return 0;
        }
      }
    };

    lastReadLine = 0;
    BPF_EventList = new PriorityQueue<>(comparator);
    BPF_ManifestEventList = new PriorityQueue<>(comparator);
    BPF_InfoList = new HashMap<>();
    BPF_BlackList = new HashSet<>();
    BlackList = new File(Blacklist_Path);
    if (BlackList.exists()) {
      try (
        BufferedReader reader = new BufferedReader(new FileReader(BlackList))
      ) {
        String line;
        while ((line = reader.readLine()) != null) {
          BPF_BlackList.add(line);
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    } else {
      System.out.println("blacklist not exist.");
      try (
        BufferedWriter writer = new BufferedWriter(
          new FileWriter(BlackList, true)
        )
      ) {
        BPF_BlackList.add("android.hardware.usb.action.USB_DEVICE_ATTACHED");
        BPF_BlackList.add("android.hardware.usb.action.USB_DEVICE_DETACHED");
        BPF_BlackList.add("android.bluetooth.device.action.PAIRING_REQUEST");
        writer.write("android.hardware.usb.action.USB_DEVICE_ATTACHED");
        writer.newLine();
        writer.write("android.hardware.usb.action.USB_DEVICE_DETACHED");
        writer.newLine();
        writer.write("android.bluetooth.device.action.PAIRING_REQUEST");
        writer.newLine();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    try {
      watchFile(JSON_Path);
    } catch (IOException e) {
      Logger.err.println(
        "AHAFuzz Failed : Error to run watchFile" + e.getMessage()
      );
    }
    // Initial Reading of JSON file
    readUpdatedContentInit(JSON_Path);
    mAgent = ApeAgent.createAgent(this);
    connect();
  }

  static PrintWriter openWriter(File logFile) {
    try {
      return new PrintWriter(new BufferedWriter(new FileWriter(logFile)));
    } catch (IOException e) {
      e.printStackTrace();
      Logger.wprintln("Cannot open " + logFile);
      System.exit(1);
    }
    return null;
  }

  public Agent getAgent() {
    return mAgent;
  }

  public File getOutputDirectory() {
    if (!this.mOutputDirectory.exists()) {
      if (!this.mOutputDirectory.mkdirs()) {
        Logger.wprintln(
          "Fail to create output directory at " + this.mOutputDirectory
        );
        Logger.wprintln("Use /data/local/tmp instead.");
        return new File("/data/local/tmp");
      }
    }
    return this.mOutputDirectory;
  }

  public String getTopActivityPackageName() {
    ComponentName cn = getTopActivityComponentName();
    if (cn != null) {
      return cn.getPackageName();
    }
    return Monkey.currentPackage;
  }

  public String getTopActivityClassName() {
    ComponentName cn = getTopActivityComponentName();
    if (cn != null) {
      return cn.getClassName();
    }
    return Monkey.currentPackage;
  }

  public ComponentName getTopActivityComponentName() {
    return AndroidDevice.getTopActivityComponentName();
  }

  /**
   * Get visible bounds of a given node.
   */
  public Rect getVisibleBounds(Rect nodeRect) {
    Rect visibleBounds = getVisibleBounds();

    if (!visibleBounds.intersect(nodeRect)) {
      return null;
    }
    return visibleBounds;
  }

  /**
   * Always return a fresh rect
   *
   * @return
   */
  protected Rect getVisibleBounds() {
    Rect bounds = mAgent.getCurrentRootNodeBounds();
    if (bounds == null) {
      Display display = DisplayManagerGlobal
        .getInstance()
        .getRealDisplay(Display.DEFAULT_DISPLAY);
      Point size = new Point();
      display.getSize(size);
      bounds = new Rect();
      bounds.top = 0;
      bounds.left = 0;
      bounds.right = size.x;
      bounds.bottom = size.y;
    } else {
      // avoid modification
      bounds = new Rect(bounds);
      Rect displayBounds = AndroidDevice.getDisplayBounds();
      if (!bounds.intersect(displayBounds)) {
        return displayBounds;
      }
    }

    return bounds;
  }

  int outOfBoundsCounter = 0;

  private boolean waitForActivity;

  private boolean clearPackageOnGeneratingActivity;

  private int lastStartTimestamp = -1;

  private boolean waitForActivityFromClean;

  protected void generateClickEventAt(Rect nodeRect, long waitTime) {
    generateClickEventAt(
      nodeRect,
      waitTime,
      useRandomClick ? ClickPoint.RANDOM : ClickPoint.CENTER
    );
  }

  enum ClickPoint {
    CENTER,
    LEFT,
    TOP,
    RIGHT,
    BOTTOM,
    TOP_LEFT,
    TOP_RIGHT,
    BOTTOM_LEFT,
    BOTTOM_RIGHT,
    RANDOM,
  }

  protected void generateClickEventAt(
    Rect nodeRect,
    long waitTime,
    ClickPoint clickPoint
  ) {
    Rect bounds = getVisibleBounds(nodeRect);
    if (bounds == null) {
      Logger.wprintln("Error to fetch bounds.");
      bounds = AndroidDevice.getDisplayBounds();
    }

    PointF p1;
    switch (clickPoint) {
      case CENTER:
        p1 = new PointF(bounds.exactCenterX(), bounds.exactCenterY());
        break;
      case LEFT:
        p1 = new PointF(bounds.left, bounds.exactCenterY());
        break;
      case TOP:
        p1 = new PointF(bounds.exactCenterX(), bounds.top);
        break;
      case RIGHT:
        p1 =
          new PointF(
            Math.min(bounds.left, bounds.right - 1),
            bounds.exactCenterY()
          );
        break;
      case BOTTOM:
        p1 =
          new PointF(
            bounds.exactCenterX(),
            Math.min(bounds.top, bounds.bottom - 1)
          );
        break;
      case TOP_LEFT:
        p1 = new PointF(bounds.left, bounds.top);
        break;
      case TOP_RIGHT:
        p1 = new PointF(Math.min(bounds.left, bounds.right - 1), bounds.top);
        break;
      case BOTTOM_RIGHT:
        p1 =
          new PointF(
            Math.min(bounds.left, bounds.right - 1),
            Math.min(bounds.top, bounds.bottom - 1)
          );
        break;
      case BOTTOM_LEFT:
        p1 = new PointF(bounds.left, Math.min(bounds.top, bounds.bottom - 1));
        break;
      case RANDOM:
        int width = bounds.width() > 0
          ? getRandom().nextInt(bounds.width())
          : 0;
        int height = bounds.height() > 0
          ? getRandom().nextInt(bounds.height())
          : 0;
        p1 = new PointF(bounds.left + width, bounds.top + height);
        break;
      default:
        throw new RuntimeException(
          "Unsupported type of clickPoint: " + clickPoint
        );
    }

    if (!bounds.contains((int) p1.x, (int) p1.y)) {
      // throw new RuntimeException("Bug");
      Logger.wformat("Invalid bounds: %s", bounds);
      return;
    }
    long downAt = SystemClock.uptimeMillis();

    addEvent(
      new MonkeyTouchEvent(MotionEvent.ACTION_DOWN)
        .setDownTime(downAt)
        .addPointer(0, p1.x, p1.y)
        .setIntermediateNote(false)
    );

    if (waitTime > 0) {
      MonkeyWaitEvent we = new MonkeyWaitEvent(waitTime);
      addEvent(we);
    }

    addEvent(
      new MonkeyTouchEvent(MotionEvent.ACTION_UP)
        .setDownTime(downAt)
        .addPointer(0, p1.x, p1.y)
        .setIntermediateNote(false)
    );
  }

  protected void generateKeyBackEvent() {
    generateKeyEvent(KeyEvent.KEYCODE_BACK);
  }

  protected void generateKeyMenuEvent() {
    generateKeyEvent(KeyEvent.KEYCODE_MENU);
    generateThrottleEvent(mThrottle);
  }

  protected void generateKeyEvent(int key) {
    generateKeyEvent(key, KeyEvent.KEYCODE_UNKNOWN);
  }

  /**
   * Generate a key event at specific key.
   */
  protected void generateKeyEvent(int key, int additionalKey) {
    if (mVerbose > 0) {
      if (!hasKey(key)) {
        Logger.println("Device has no key " + getKeyName(key));
      }
    }
    MonkeyKeyEvent e;
    if (additionalKey != KeyEvent.KEYCODE_UNKNOWN) {
      e = new MonkeyKeyEvent(KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_SHIFT_LEFT);
      addEvent(e);
    }

    e = new MonkeyKeyEvent(KeyEvent.ACTION_DOWN, key);
    addEvent(e);

    e = new MonkeyKeyEvent(KeyEvent.ACTION_UP, key);
    addEvent(e);

    if (additionalKey != KeyEvent.KEYCODE_UNKNOWN) {
      e = new MonkeyKeyEvent(KeyEvent.ACTION_UP, KeyEvent.KEYCODE_SHIFT_LEFT);
      addEvent(e);
    }
  }

  /**
   * ActiveWindow may not belong to activity package.
   *
   * @return
   */
  public AccessibilityNodeInfo getRootInActiveWindow() {
    return mUiAutomation.getRootInActiveWindow();
  }

  public AccessibilityNodeInfo getRootInActiveWindowSlow() {
    try {
      mUiAutomation.waitForIdle(1000, 1000 * 10);
    } catch (TimeoutException e) {
      e.printStackTrace();
    }
    return mUiAutomation.getRootInActiveWindow();
  }

  /* private */static final int GESTURE_TAP = 0;
  private static final int GESTURE_DRAG = 1;
  private static final int GESTURE_PINCH_OR_ZOOM = 2;
  private static final int[] NAV_KEYS = {
    KeyEvent.KEYCODE_DPAD_UP,
    KeyEvent.KEYCODE_DPAD_DOWN,
    KeyEvent.KEYCODE_DPAD_LEFT,
    KeyEvent.KEYCODE_DPAD_RIGHT,
  };
  /**
   * Key events that perform major navigation options (so shouldn't be sent as
   * much).
   */
  private static final int[] MAJOR_NAV_KEYS = {
    KeyEvent.KEYCODE_MENU,/*
     * KeyEvent
     * .
     * KEYCODE_SOFT_RIGHT,
     */
    KeyEvent.KEYCODE_DPAD_CENTER,
  };
  /** Key events that perform system operations. */
  private static final int[] SYS_KEYS = {
    // KeyEvent.KEYCODE_HOME, KeyEvent.KEYCODE_BACK,
    // KeyEvent.KEYCODE_CALL, KeyEvent.KEYCODE_ENDCALL,
    KeyEvent.KEYCODE_VOLUME_UP,
    KeyEvent.KEYCODE_VOLUME_DOWN,
    KeyEvent.KEYCODE_VOLUME_MUTE,
    KeyEvent.KEYCODE_MUTE,
  };
  /** If a physical key exists? */
  private static final boolean[] PHYSICAL_KEY_EXISTS = new boolean[KeyEvent.getMaxKeyCode() +
  1];

  static {
    for (int i = 0; i < PHYSICAL_KEY_EXISTS.length; ++i) {
      PHYSICAL_KEY_EXISTS[i] = true;
    }
    // Only examine SYS_KEYS
    for (int i = 0; i < SYS_KEYS.length; ++i) {
      PHYSICAL_KEY_EXISTS[SYS_KEYS[i]] =
        KeyCharacterMap.deviceHasKey(SYS_KEYS[i]);
    }
  }

  protected void generateFuzzingMajorNavKeyEvents() {
    int lastKey = MAJOR_NAV_KEYS[mRandom.nextInt(MAJOR_NAV_KEYS.length)];
    generateKeyEvent(lastKey);
  }

  protected void generateFuzzingNavKeyEvents() {
    int lastKey = NAV_KEYS[mRandom.nextInt(NAV_KEYS.length)];
    generateKeyEvent(lastKey);
  }

  protected void generateFuzzingSysKeyEvents() {
    int lastKey = SYS_KEYS[mRandom.nextInt(SYS_KEYS.length)];
    generateKeyEvent(lastKey);
  }

  protected PointF randomPoint(Random random, int width, int height) {
    return new PointF(random.nextInt(width), random.nextInt(height));
  }

  protected PointF randomVector(Random random) {
    return new PointF(
      (random.nextFloat() - 0.5f) * 50,
      (random.nextFloat() - 0.5f) * 50
    );
  }

  protected void randomWalk(
    Random random,
    int width,
    int height,
    PointF point,
    PointF vector
  ) {
    point.x =
      (float) Math.max(
        Math.min(point.x + random.nextFloat() * vector.x, width),
        0
      );
    point.y =
      (float) Math.max(
        Math.min(point.y + random.nextFloat() * vector.y, height),
        0
      );
  }

  protected void generatePointerEvent(PointF p1, Random random, int gesture) {
    Rect bounds = getVisibleBounds();
    int width = bounds.right;
    int height = bounds.bottom;

    if (p1 == null) {
      p1 = randomPoint(random, width, height);
    }
    PointF v1 = randomVector(random);

    long downAt = SystemClock.uptimeMillis();

    addEvent(
      new MonkeyTouchEvent(MotionEvent.ACTION_DOWN)
        .setDownTime(downAt)
        .addPointer(0, p1.x, p1.y)
        .setIntermediateNote(false)
    );

    // sometimes we'll move during the touch
    if (gesture == GESTURE_DRAG) {
      int count = random.nextInt(10);
      for (int i = 0; i < count; i++) {
        randomWalk(random, width, height, p1, v1);

        addEvent(
          new MonkeyTouchEvent(MotionEvent.ACTION_MOVE)
            .setDownTime(downAt)
            .addPointer(0, p1.x, p1.y)
            .setIntermediateNote(true)
        );
      }
    } else if (gesture == GESTURE_PINCH_OR_ZOOM) {
      PointF p2 = randomPoint(random, width, height);
      PointF v2 = randomVector(random);

      randomWalk(random, width, height, p1, v1);
      addEvent(
        new MonkeyTouchEvent(
          MotionEvent.ACTION_POINTER_DOWN |
          (1 << MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        )
          .setDownTime(downAt)
          .addPointer(0, p1.x, p1.y)
          .addPointer(1, p2.x, p2.y)
          .setIntermediateNote(true)
      );

      int count = random.nextInt(10);
      for (int i = 0; i < count; i++) {
        randomWalk(random, width, height, p1, v1);
        randomWalk(random, width, height, p2, v2);

        addEvent(
          new MonkeyTouchEvent(MotionEvent.ACTION_MOVE)
            .setDownTime(downAt)
            .addPointer(0, p1.x, p1.y)
            .addPointer(1, p2.x, p2.y)
            .setIntermediateNote(true)
        );
      }

      randomWalk(random, width, height, p1, v1);
      randomWalk(random, width, height, p2, v2);
      addEvent(
        new MonkeyTouchEvent(
          MotionEvent.ACTION_POINTER_UP |
          (1 << MotionEvent.ACTION_POINTER_INDEX_SHIFT)
        )
          .setDownTime(downAt)
          .addPointer(0, p1.x, p1.y)
          .addPointer(1, p2.x, p2.y)
          .setIntermediateNote(true)
      );
    }

    randomWalk(random, width, height, p1, v1);
    addEvent(
      new MonkeyTouchEvent(MotionEvent.ACTION_UP)
        .setDownTime(downAt)
        .addPointer(0, p1.x, p1.y)
        .setIntermediateNote(false)
    );
  }

  private boolean validateClickAction(ModelAction action) {
    return validateBounds(action);
  }

  private boolean validateBounds(ModelAction action) {
    GUITreeNode node = action.getResolvedNode();
    return !node.isEmpty() && !node.isOutOfRoot();
  }

  private boolean validateScrollAction(ModelAction action) {
    return validateBounds(action);
  }

  public boolean validateResolvedAction(ModelAction action) {
    switch (action.getType()) {
      case EVENT_START:
      case EVENT_RESTART:
      case EVENT_CLEAN_RESTART:
      case EVENT_NOP:
      case EVENT_ACTIVATE:
        return true;
      case MODEL_BACK:
        return true;
      case MODEL_CLICK:
      case MODEL_LONG_CLICK:
        return validateClickAction(action);
      case MODEL_SCROLL_BOTTOM_UP:
      case MODEL_SCROLL_TOP_DOWN:
      case MODEL_SCROLL_LEFT_RIGHT:
      case MODEL_SCROLL_RIGHT_LEFT:
        return validateScrollAction(action);
      default:
        throw new RuntimeException("Should not reach here");
    }
  }

  protected void generateActivateEvent() {
    Logger.iprintln("Activating: generate app switch events.");
    generateAppSwitchEvent();
    mAgent.startNewEpisode();
  }

  void generateRotationEvent(Random random) {
    addEvent(
      new MonkeyRotationEvent(
        SCREEN_ROTATION_DEGREES[random.nextInt(SCREEN_ROTATION_DEGREES.length)],
        random.nextBoolean()
      )
    );
  }

  void resetRotation() {
    addEvent(new MonkeyRotationEvent(Surface.ROTATION_0, false));
  }

  private final boolean hasEvent() {
    return !mQ.isEmpty();
  }

  private final void addEvent(MonkeyEvent event) {
    mQ.addLast(event);
    event.setEventId(mEventId++);
    ApeRRFormatter.logProduce(mEventProduceLogger, event);
  }

  private final void clearEvent() {
    while (!mQ.isEmpty()) {
      MonkeyEvent e = mQ.removeFirst();
      ApeRRFormatter.logDrop(mEventConsumeLogger, e);
    }
  }

  private final MonkeyEvent popEvent() {
    return mQ.removeFirst();
  }

  void generateTrackballEvent() {
    Random random = mRandom;
    for (int i = 0; i < 10; ++i) {
      // generate a small random step
      int dX = random.nextInt(10) - 5;
      int dY = random.nextInt(10) - 5;

      addEvent(
        new MonkeyTrackballEvent(MotionEvent.ACTION_MOVE)
          .addPointer(0, dX, dY)
          .setIntermediateNote(i > 0)
      );
    }

    // 10% of trackball moves end with a click
    if (0 == random.nextInt(10)) {
      long downAt = SystemClock.uptimeMillis();

      addEvent(
        new MonkeyTrackballEvent(MotionEvent.ACTION_DOWN)
          .setDownTime(downAt)
          .addPointer(0, 0, 0)
          .setIntermediateNote(true)
      );

      addEvent(
        new MonkeyTrackballEvent(MotionEvent.ACTION_UP)
          .setDownTime(downAt)
          .addPointer(0, 0, 0)
          .setIntermediateNote(false)
      );
    }
  }

  protected void generateScrollEventAt(Action action) {
    Rect displayBounds = AndroidDevice.getDisplayBounds();
    Rect nodeRect = action.getResolvedNode().getBoundsInScreen();
    if (!nodeRect.intersect(displayBounds)) {
      Logger.wformat("Action " + action + " should be validated first!");
      nodeRect = displayBounds;
    }
    PointF start = new PointF(nodeRect.exactCenterX(), nodeRect.exactCenterY());
    PointF end = null;
    ActionType type = action.getType();
    switch (type) {
      case MODEL_SCROLL_BOTTOM_UP:
        int top = getStatusBarHeight();
        if (top < displayBounds.top) {
          top = displayBounds.top;
        }
        end = new PointF(start.x, top); // top is inclusive
        break;
      case MODEL_SCROLL_TOP_DOWN:
        end = new PointF(start.x, displayBounds.bottom - 1); // bottom is
        // exclusive
        break;
      case MODEL_SCROLL_LEFT_RIGHT:
        end = new PointF(displayBounds.right - 1, start.y); // right is
        // exclusive
        break;
      case MODEL_SCROLL_RIGHT_LEFT:
        end = new PointF(displayBounds.left, start.y); // left is inclusive
        break;
      default:
        throw new RuntimeException("Should not reach here");
    }
    long downAt = SystemClock.uptimeMillis();

    addEvent(
      new MonkeyTouchEvent(MotionEvent.ACTION_DOWN)
        .setDownTime(downAt)
        .addPointer(0, start.x, start.y)
        .setIntermediateNote(false)
    );

    long duration = swipeDuration;
    int steps = 10;
    long waitTime = duration / steps;
    for (int i = 0; i < steps; i++) {
      float alpha = i / (float) steps;
      addEvent(
        new MonkeyTouchEvent(MotionEvent.ACTION_MOVE)
          .setDownTime(downAt)
          .addPointer(
            0,
            lerp(start.x, end.x, alpha),
            lerp(start.y, end.y, alpha)
          )
          .setIntermediateNote(true)
      );
      addEvent(new MonkeyWaitEvent(waitTime));
    }

    addEvent(
      new MonkeyTouchEvent(MotionEvent.ACTION_UP)
        .setDownTime(downAt)
        .addPointer(0, end.x, end.y)
        .setIntermediateNote(false)
    );
  }

  private static final float lerp(float a, float b, float alpha) {
    return (b - a) * alpha + a;
  }

  void sleep(long time) {
    try {
      Thread.sleep(time);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  static void printInfo(String tab, int index, AccessibilityNodeInfo info) {
    if (info == null) {
      Logger.format("%s[%d]null info", tab, index);
      return;
    }
    Logger.format(
      "%s[%d] %s %s %s",
      tab,
      index,
      info.getPackageName(),
      info.getClassName(),
      info.getBoundsInScreen()
    );
    tab = tab + "\t";
    for (int i = 0; i < info.getChildCount(); i++) {
      AccessibilityNodeInfo child = info.getChild(i);
      printInfo(tab, i, child);
    }
  }

  /**
   * generate a random event based on mFactor
   */
  protected void generateEvents() {
    if (hasEvent()) {
      Logger.BPFprintln("Event Already exists, Skip");
      return;
    }
    activityLoadingCount = 0;

    ComponentName topComp = null;
    AccessibilityNodeInfo info = null;
    int repeat = refectchInfoCount;

    Action action = null;
    while (repeat-- > 0) {
      topComp = this.getTopActivityComponentName();
      info = getRootInActiveWindow();
      // this two operations may not be the same
      if (info == null) {
        sleep(refectchInfoWaitingInterval);
        continue;
      }
      if (info != null) {
        nullInfoCounter = 0;
        action = mAgent.updateState(topComp, info);
        if (action == null) {
          throw new NullPointerException("Resolved action should not be null");
        }
        break;
      }
    }
    if (info == null) {
      Logger.wprintln(
        "Null info root node returned by UiTestAutomationBridge, generate activate action..."
      );
      nullInfoCounter++;
      if (nullInfoCounter > 10) {
        stopTopActivity();
        nullInfoCounter = 0;
      }
      mAgent.onVoidGUITree(nullInfoCounter);
      AndroidDevice.checkInteractive();
      action = Action.ACTIVATE;
    }
    if (action == null) {
      action = Action.NOP;
    }
    generateEventsForAction(action);
    if (doFuzzing && RandomHelper.toss(fuzzingRate)) {
      if (mAgent.canFuzzing()) {
        Action fuzzingAction = mAgent.generateFuzzingAction();
        generateEventsForAction(fuzzingAction);
      }
    }
    mAgent.notifyActionConsumed();
  }


  public static void penaltyIntent(String stackTrace) {
    String targetaction = "";
    for (String key : BPF_InfoList.keySet()) {
      if (stackTrace.contains(key) && !BPF_BlackList.contains(key)) {
        targetaction = key;
        break;
      }
    }
    return;
  }

  // ====================================================================================
  //
  // SECTION 4: INTENT EVENT GENERATION
  //
  // These methods manage the generation of intent fuzzing events:
  // - generateBPFEvent()          : Main intent event generation from BPF queue
  // - printEventList()            : Debug output for event queue
  // - checkBlackList()            : Filter problematic intents
  // - generateBPFManifestEvent()  : Manifest-declared intent handling
  // - reGenerateManifestIntent()  : Re-queue manifest intents on app restart
  //
  // ====================================================================================

  // AHAFuzz: Generate broadcast intent event from BPF feedback
  public void generateBPFEvent() {
    Logger.BPFprintln("generateBPFEvent!!!! Manifest intent");
    if (!(BPF_EventList.isEmpty())) { // If BPFEvent is empty, then re-generate events
      try {
        if (!(BPF_EventList.isEmpty())) {
          JSONObject data = BPF_EventList.poll();
          if (checkBlackList(data)) {
            Logger.BPFprintln("blacklist called!! " + data.toString());
            generateBPFEvent();
            return;
          }
          Logger.BPFprintln(" Intent selected from queue: " + data.toString());
          String intent_action = (String) data.get("action");
          if (intent_action.contains("Explicit_Intent")) {
            String ExplicitClassname = (String) data.get("name");
            BPF_InfoList.get(ExplicitClassname).set(EXIST, NONEXIST);
            lastIntentAction = ExplicitClassname;
          } else {
            BPF_InfoList.get(intent_action).set(EXIST, NONEXIST);
            lastIntentAction = intent_action;
          }
          AHAIntentEvent e = new AHAIntentEvent(data, mMainApps);
          mQ.addLast(e);
          generateThrottleEvent(mThrottle);
        }
      } catch (Exception e) {
        Logger.BPFprintln("BPF eventlist is empty" + e.getMessage());
      }
    } else {
      Logger.BPFprintln("No BPF Event, call generateEvents())");
      reGenerateManifestIntent();
      generateEvents();
    }
    if (manifestCount > 10) {
      Logger.BPFprintln("Re-generate Manifest intent");
      ScoreBaseline -= 1;
      manifestCount = 0;
    }
    manifestCount += 1;
    printEventList();
  }

  public void printEventList() {
    Iterator<JSONObject> iterator = BPF_EventList.iterator();
    while (iterator.hasNext()) {
      JSONObject jsonObject = iterator.next();
      Logger.BPFprintln(jsonObject.toString());
    }
  }


  public Boolean checkBlackList(JSONObject intent) {
    try {
      String intent_action = (String) intent.get("action");
      if (intent_action.contains("hardware")){
        return true;
      }
      if (intent_action.contains("Explicit_Intent")) {
        intent_action = (String) intent.get("name");
      }
      if (BPF_BlackList.contains(intent_action)) {
        int IntentSymLen = ((JSONObject) intent.get("symbol_table")).length();
        int lastIntentSymLen = BPF_InfoList.get(intent_action).get(KEYNUM);
        int discover_new = (int) intent.get("discover_new");
        if (
          IntentSymLen == 0 ||
          discover_new == 0 ||
          lastIntentSymLen - IntentSymLen == 0
        ) {
          return true;
        }
      }
      return false;
    } catch (Exception e) {
      Logger.BPFprintln("checkBlackList json parsing error " + e.getMessage());
      return false;
    }
  }

  public void generateBPFManifestEvent() {
    Logger.BPFprintln(" Generating manifest intent event");
    if (!(BPF_ManifestEventList.isEmpty())) {
      try {
        JSONObject data = BPF_ManifestEventList.poll();
        AHAIntentEvent e = new AHAIntentEvent(data, mMainApps);
        mQ.addLast(e);
        BPF_ManifestEventList.add(data);
      } catch (Exception e) {
        Logger.BPFprintln(
          "BPF Manifesteventlist is empty, Cannot reach here, " + e.getMessage()
        );
      }
    } else {
      Logger.BPFprintln(
        "Manifest intent is empty, skip generateBPFManifestEvent()"
      );
    }
  }

  public void reGenerateManifestIntent() {
    if (!(BPF_ManifestEventList.isEmpty())) {
      Logger.BPFprintln(" Re-generating manifest intents from pool");
      try {
        if (!(BPF_EventList.isEmpty())) {
          JSONObject data = BPF_EventList.poll();
          String intentFlag = (String) data.get("init");
          BPF_EventList.add(data);
          if (intentFlag.contains("manifest")) {
            return;
          }
        }
        Iterator<JSONObject> iterator = BPF_ManifestEventList.iterator();
        while (iterator.hasNext()) {
          JSONObject jsonObject = iterator.next();
          String intent_action = (String) jsonObject.get("action");
          List<Integer> intentinfo;
          if (intent_action.contains("Explicit_Intent")) {
            String ExplicitClassname = (String) jsonObject.get("name");
            intentinfo = BPF_InfoList.get(ExplicitClassname);
          } else {
            intentinfo = BPF_InfoList.get(intent_action);
          }
          if (intentinfo.get(EXIST) == NONEXIST) {
            intentinfo.set(EXIST, EXISTING);
            jsonObject.put("score", ScoreBaseline - 3);
            BPF_EventList.add(jsonObject);
          }
        }
      } catch (Exception e) {
        Logger.BPFprintln(
          "BPF Manifesteventlist is empty, skip this operation, " +
          e.getMessage()
        );
      }
    } else {
      Logger.BPFprintln(
        "Manifest intent is empty, skip reGenerateManifestIntent()"
      );
    }
  }

 // * ====================================================================================

  protected void startRandomMainApp() {
    Logger.BPFprintln("startRandomMainApp called!!");
    generateEventsForAction(
      Action.getStartAction(ActionType.EVENT_START, randomlyPickMainApp())
    );
  }

  private void generateEventsForActionInternal(Action action) {
    switch (action.getType()) {
      case FUZZ:
        generateFuzzingEvents((FuzzAction) action);
        break;
      case EVENT_START:
        generateActivityEvents(((StartAction) action).getActivity(), false);
        break;
      case EVENT_RESTART:
        restartPackage(
          ((StartAction) action).getActivity(),
          false,
          "start action"
        );
        break;
      case EVENT_CLEAN_RESTART:
        restartPackage(
          ((StartAction) action).getActivity(),
          true,
          "start action"
        );
        break;
      case EVENT_NOP:
        generateThrottleEvent(action.getThrottle());
        break;
      case EVENT_ACTIVATE:
        generateActivateEvent();
        break;
      case MODEL_BACK:
        generateKeyBackEvent();
        break;
      case MODEL_CLICK:
        GUITreeNode node = action.getResolvedNode();
        generateClickEventAt(
          action.getResolvedNode().getBoundsInScreen(),
          CLICK_WAIT_TIME
        );
        if (node != null && node.getInputText() != null) {
          generateThrottleEvent(200); // Let the click event to be scheduled
          doInput(action, node);
        }
        break;
      case MODEL_LONG_CLICK:
        generateClickEventAt(
          action.getResolvedNode().getBoundsInScreen(),
          LONG_CLICK_WAIT_TIME
        );
        break;
      case MODEL_SCROLL_BOTTOM_UP:
      case MODEL_SCROLL_TOP_DOWN:
      case MODEL_SCROLL_LEFT_RIGHT:
      case MODEL_SCROLL_RIGHT_LEFT:
        generateScrollEventAt(action);
        break;
      default:
        throw new RuntimeException("Should not reach here");
    }
  }

  private void generateFuzzingEvents(FuzzAction action) {
    List<ApeEvent> events = action.getFuzzingEvents();
    long throttle = mThrottle + action.getThrottle();
    for (ApeEvent event : events) {
      List<MonkeyEvent> monkeyEvents = event.generateMonkeyEvents();
      for (MonkeyEvent me : monkeyEvents) {
        if (me == null) {
          throw new RuntimeException();
        }
        addEvent(me);
      }
      generateThrottleEvent(throttle);
    }
    Logger.iprintln("Fuzzing: reset rotation.");
    resetRotation();
    // avoid non-deterministic actions
    mAgent.startNewEpisode();
  }

  private void generateEventsForAction(Action action) {
    long clockTimestamp = System.currentTimeMillis();
    startLogAction(clockTimestamp, action);
    mAgent.appendToActionHistory(clockTimestamp, action);
    generateEventsForActionInternal(action);
    long throttle = mThrottle + action.getThrottle();
    generateThrottleEvent(throttle);
    endLogAction(action);
  }

  protected boolean checkPackage(
    ComponentName topComp,
    AccessibilityNodeInfo info
  ) {
    String packageName = topComp.getPackageName();
    String infoPkg = info.getPackageName().toString();
    if (!infoPkg.equals(packageName)) {
      Logger.wformat(
        "Different packages: top(%s) v.s. info(%s).",
        packageName,
        infoPkg
      );
      return false;
    }
    if (!MonkeyUtils.getPackageFilter().checkEnteringPackage(packageName)) {
      Logger.format("Disallowed package: %s", packageName);
      return false;
    }
    return true;
  }

  public void clearPackage(String packageName) {
    if (isIntentEvent) {
      BPF_InfoList.get(lastIntentAction).set(COVERAGE, -5);
    }
    
    String[] permissions = this.packagePermissions.get(packageName);
    if (permissions == null) {
      Logger.wprintln("Stop clearing untracked package: " + packageName);
      return;
    }
    AndroidDevice.clearPackage(packageName, permissions);
  }

  public void grantRuntimePermissions(String packageName, String reason) {
    String[] permissions = this.packagePermissions.get(packageName);
    if (permissions == null) {
      Logger.wprintln(
        "Stop granting permissions to untracked package: " + packageName
      );
      return;
    }
    AndroidDevice.grantRuntimePermissions(packageName, permissions, reason);
  }

  public void grantRuntimePermissions(String reason) {
    for (ComponentName cn : mMainApps) {
      grantRuntimePermissions(cn.getPackageName(), reason);
    }
  }

  protected void restartPackage(
    ComponentName cn,
    boolean clearPackage,
    String reason
  ) {
    String packageName = cn.getPackageName();
    Logger.iprintln("Try to restart package " + packageName + " for " + reason);
    stopPackage(cn.getPackageName());
    generateActivityEvents(cn, clearPackage);
  }

  /**
   * Stop the foreground activity
   */
  public void stopTopActivity() {
    boolean killed = false;
    try {
      List<RunningAppProcessInfo> processes = AndroidDevice.iActivityManager.getRunningAppProcesses();
      if (!processes.isEmpty()) {
        RunningAppProcessInfo process = processes.get(0);
        Logger.format(
          "Try to stop process %s(%d) ",
          process.processName,
          process.pid
        );
        // mDevice.mAm.killPids(new int[] {process.pid}, "Killed by
        // ape", true);
        if (AndroidDevice.killPids(process.pid) == 0) { // only when you are
          // rooted
          killed = true;
          Logger.format(
            "Process %s(%d) is killed",
            process.processName,
            process.pid
          );
        }
      }
      mAgent.onActivityStopped();
    } catch (RemoteException e1) {
      e1.printStackTrace();
      killed = false;
    }

    if (!killed) {
      stopPackages();
    }
    AndroidDevice.checkInteractive();
  }

  void stopPackages() {
    for (ComponentName cn : mMainApps) {
      stopPackage(cn.getPackageName());
    }
  }

  void stopPackage(String packageName) {
    if (AndroidDevice.stopPackage(packageName)) {
      Logger.iformat("Package %s has been stopped", packageName);
    } else {
      Logger.wformat("Package %s has NOT been stopped", packageName);
    }
  }

  protected void generateFuzzingEvents() {
    int repeat = RandomHelper.nextBetween(10, 20);
    while (repeat > 0) {
      repeat--;
      int eventType = RandomHelper.nextInt(20);
      switch (eventType) {
        case 0:
          Logger.iprintln("Fuzzing: generate rotation events.");
          generateRotationEvent(getRandom());
          break;
        case 1:
          Logger.iprintln("Fuzzing: generate app switch events.");
          generateAppSwitchEvent();
          break;
        case 2:
        case 3:
        case 4:
        case 5:
          Logger.iprintln("Fuzzing: generate major navigation events.");
          if (RandomHelper.nextBoolean()) {
            generateTrackballEvent();
          }
          for (int i = 0; i < 5; i++) {
            if (RandomHelper.nextBoolean()) {
              generateFuzzingNavKeyEvents();
            } else {
              generateFuzzingMajorNavKeyEvents();
            }
          }
          if (RandomHelper.nextBoolean()) {
            generateTrackballEvent();
          }
          break;
        case 6:
        case 7:
        case 8:
          Logger.iprintln("Fuzzing: generate system key events.");
          generateFuzzingSysKeyEvents();
          break;
        case 9:
        case 10:
          Logger.iprintln("Fuzzing: generate system key events.");
          int lastKey;
          while (true) {
            lastKey = 1 + mRandom.nextInt(KeyEvent.getMaxKeyCode() - 1);
            if (
              lastKey != KeyEvent.KEYCODE_POWER &&
              lastKey != KeyEvent.KEYCODE_ENDCALL &&
              lastKey != KeyEvent.KEYCODE_SLEEP &&
              PHYSICAL_KEY_EXISTS[lastKey]
            ) {
              break;
            }
          }
          generateKeyEvent(lastKey);
          break;
        case 11:
        case 12:
          Logger.iprintln("Fuzzing: generate trackball.");
          generateTrackballEvent();
          break;
        default:
          switch (eventType % 3) {
            case 0:
              Logger.iprintln("Fuzzing: generate drag.");
              generatePointerEvent(null, mRandom, GESTURE_DRAG);
              break;
            case 1:
              Logger.iprintln("Fuzzing: generate pinch or zoom.");
              generatePointerEvent(null, mRandom, GESTURE_PINCH_OR_ZOOM);
              break;
            default:
              Logger.iprintln("Fuzzing: generate random click.");
              generateRandomClick(RandomHelper.toss(0.1D));
              break;
          }
      }
      generateThrottleEvent(mThrottle);
    }
    Logger.iprintln("Fuzzing: reset rotation.");
    resetRotation();
    // avoid non-deterministic actions
    mAgent.startNewEpisode();
  }

  void generateRandomClick(boolean longClick) {
    Rect rect = getVisibleBounds();
    generateClickEventAt(
      rect,
      (longClick ? LONG_CLICK_WAIT_TIME : CLICK_WAIT_TIME),
      ClickPoint.RANDOM
    );
  }

  private void generateAppSwitchEvent() {
    generateKeyEvent(KeyEvent.KEYCODE_APP_SWITCH);
    generateThrottleEvent(500);
    if (RandomHelper.nextBoolean()) {
      Logger.println("Press HOME after app switch");
      generateKeyEvent(KeyEvent.KEYCODE_HOME);
    } else {
      Logger.println("Press BACK after app switch");
      generateKeyBackEvent();
    }
    generateThrottleEvent(mThrottle);
  }

  private void startLogAction(long clockTimestamp, Action action) {
    ApeRRFormatter.startLogAction(
      mEventProduceLogger,
      action,
      clockTimestamp,
      mAgent.getTimestamp()
    );
  }

  private void endLogAction(Action action) {
    ApeRRFormatter.endLogAction(
      mEventProduceLogger,
      action,
      mAgent.getTimestamp()
    );
  }

  protected void generateThrottleEvent(long base) {
    // base = base;
    base = base * 2; // taint analysis mode
    long throttle = base;
    if (mRandomizeThrottle && (mThrottle > 0)) {
      throttle = mRandom.nextLong();
      if (throttle < 0) {
        throttle = -throttle;
      }
      throttle %= base;
      ++throttle;
    }
    if (throttle < 0) {
      throttle = -throttle;
    }
    addEvent(new MonkeyThrottleEvent(throttle));
  }

  public boolean validate() {
    return mHandlerThread.isAlive();
  }

  public void setVerbose(int verbose) {
    mVerbose = verbose;
  }

  public synchronized void requestClearPackage() {
    this.clearPackageOnGeneratingActivity = true;
  }

  public ComponentName randomlyPickMainApp() {
    int total = mMainApps.size();
    int index = mRandom.nextInt(total);
    ComponentName app = mMainApps.get(index);
    return app;
  }

  /**
   * generate an activity event
   */
  protected void generateActivityEvents(
    ComponentName app,
    boolean clearPackage
  ) {
    int timestamp = this.mAgent.getTimestamp();
    boolean cleared = false;
    if (clearPackage) {
      clearPackage(app.getPackageName());
      cleared = true;
      
      // ====================================================================================
      // AHAFuzz: Re-generate manifest intents after package clear
      // ====================================================================================
      Logger.BPFprintln("clearPackage called, call reGenerateManifestIntent");
      reGenerateManifestIntent();
      // ====================================================================================
    } else {
      synchronized (this) {
        if (this.clearPackageOnGeneratingActivity) {
          clearPackage(app.getPackageName());
          cleared = true;
          clearPackageOnGeneratingActivity = false;
        }
      }
    }
    if (timestamp == lastStartTimestamp && !cleared) {
      Logger.wformat(
        "lastStartTimestamp [%d] is not updated. Try to clear package.",
        lastStartTimestamp
      );
      clearPackage(app.getPackageName());
      cleared = true;
      
      // ====================================================================================
      // AHAFuzz: Re-generate manifest intents after package clear
      // ====================================================================================
      Logger.BPFprintln("clearPackage called, call reGenerateManifestIntent");
      reGenerateManifestIntent();
      // ====================================================================================
    }
    MonkeyActivityEvent e = new MonkeyActivityEvent(app);
    addEvent(e);
    
    // ====================================================================================
    // AHAFuzz: Extended waiting time for first app load
    // ====================================================================================
    // First-time app loading requires more time for eBPF initialization
    if (FirstTimeLoad) {
      generateThrottleEvent(20000); // Wait 20s for first app load
      FirstTimeLoad = false;
    } else {
      generateThrottleEvent(5000); // Wait 5s for subsequent loads
    }
    // ====================================================================================
    this.mAgent.startNewEpisode();
    Logger.iprintln("Let's wait for activity loading...");
    this.waitForActivity = true;
    if (mEventCount == 0) {
      this.waitForActivityFromClean = true; 
    } else {
      this.waitForActivityFromClean = cleared;
    }
    this.lastStartTimestamp = timestamp;
  }

  protected void checkAppActivity() {
    ComponentName cn = getTopActivityComponentName();
    if (cn == null) {
      clearEvent();
      startRandomMainApp();
      return;
    }
    String pkg = cn.getPackageName();
    boolean allow = MonkeyUtils.getPackageFilter().isPackageValid(pkg);
    if (allow) {
      if (this.waitForActivity) {
        Logger.iformat("Expected activity package [%s] is loaded...", pkg);
        // needed.
        mAgent.onAppActivityStarted(cn, this.waitForActivityFromClean);
        this.waitForActivity = false; // we found the activity we
        this.waitForActivityFromClean = false;
      }
      return;
    }
    if (this.waitForActivity) {
      Logger.iprintln(
        "We are still waiting for activity loading. Let's wait for another 100ms..."
      );
      generateThrottleEvent(100);
      activityLoadingCount += 1;
      if (activityLoadingCount > 20) {
        throw new IllegalStateException();
      }
      return;
    }
    if (
      cn.getPackageName().equals("com.android.systemui") &&
      cn.getClassName().equals("com.android.systemui.recents.RecentsActivity")
    ) {
      if (hasEvent()) {
        Logger.dformat("The top component [%s] belongs to systemui.", cn);
        return;
      }
    } else {
      Logger.dformat("The top activity package %s is not allowed.", pkg);
    }
    mAgent.onActivityBlocked(cn);
    clearEvent();
    startRandomMainApp();
    return;
  }

  protected void generateClearEvent(GUITreeNode node) {
    Rect bounds = node.getBoundsInScreen();
    int lines = 1;
    if (node.getNodeInfo() != null) {
      AccessibilityNodeInfo info = node.getNodeInfo();
      if (info.getText() != null) {
        String fullText = info.getText().toString();
        if (fullText.isEmpty()) {
          return;
        }
        lines = fullText.split(System.lineSeparator()).length;
      }
    }
    // 1) Move cursor to the top left
    generateClickEventAt(bounds, CLICK_WAIT_TIME, ClickPoint.TOP_LEFT);
    generateThrottleEvent(50);
    // 2) Select all lines
    while (lines-- > 0) {
      generateKeyEvent(KeyEvent.KEYCODE_DPAD_DOWN, KeyEvent.KEYCODE_SHIFT_LEFT);
    }
    generateThrottleEvent(50);
    // 3) Delete selected text
    generateKeyEvent(KeyEvent.KEYCODE_DEL);
    generateThrottleEvent(100);
  }

  int lastInputTimestamp;

  private void doInput(Action action, GUITreeNode node) {
    if (lastInputTimestamp == mAgent.getTimestamp()) {
      Logger.wprintln("checkVirtualKeyboard: Input only once.");
    } else {
      lastInputTimestamp = mAgent.getTimestamp();
    }
    String inputText = node.getInputText();
    if (inputText != null) {
      Logger.iprintln("Input text is " + inputText);
      generateClearEvent(node);
      if (!AndroidDevice.sendText(inputText)) {
        attempToSendTextByKeyEvents(inputText);
      }
    } else {
      if (node.isEditText() || AndroidDevice.isVirtualKeyboardOpened()) {
        generateKeyEvent(KeyEvent.KEYCODE_ESCAPE);
      }
    }
  }

  private void attempToSendTextByKeyEvents(String inputText) {
    char[] szRes = inputText.toCharArray(); // Convert String to Char array
    char[] one = new char[1];
    for (int i = 0; i < szRes.length; i++) {
      one[0] = szRes[i];
      if (CharMap.getEvents(one) == null) {
        szRes[i] = ' ';
      }
    }

    KeyEvent[] events = CharMap.getEvents(szRes);

    for (int i = 0; i < events.length; i++) {
      MonkeyKeyEvent e = new MonkeyKeyEvent(events[i]);
      addEvent(e);
    }
    generateKeyEvent(KeyEvent.KEYCODE_ENTER);
    generateThrottleEvent(200);
  }

  /**
   * if the queue is empty, we generate events first
   *
   * @return the first event in the queue
   * 
   * ====================================================================================
   * AHAFuzz: Modified to include GUI/Intent event scheduling
   * ====================================================================================
   * 
   * SECTION 5 : SCHEDULING LOGIC 
   * 
   * This is the scheduling method that decides between GUI and Intent events.
   * Called repeatedly by the Monkey framework to get the next event to inject.
   * 
   * Key components:
   * - Dynamic ratio calculation (currentGUIRatio vs target GuiIntentEventRatio)
   * - Probability-based event selection via calculateProbability()
   * - Event counter updates (GUIEventCnt, IntentEventCnt)
   * 
   * EXECUTION FLOW:
   * 1. Check if event queue already has events → return directly
   * 3. Calculate current GUI/Intent ratio
   * 4. Use probability to decide: GUI event OR Intent event
   * 5. Update counters and generate selected event type
   * ====================================================================================
   */
  public MonkeyEvent getNextEvent() {
    if (!(mAgent instanceof ReplayAgent)) {
      checkAppActivity();
    }
    // ====================================================================================
    // AHAFuzz: GUI/Intent Event Scheduling Logic
    // ====================================================================================
    if (!hasEvent()) {
      
      try {
          // Calculate current event distribution ratios
          double currentGUIRatio = (double) GUIEventCnt / (GUIEventCnt + IntentEventCnt);
          double currentIntentRatio = (double) IntentEventCnt / (GUIEventCnt + IntentEventCnt);
          double randomValue = mRandom.nextDouble();

          // Dynamic scheduling: adjust probability based on target ratio
          if (randomValue < calculateProbability(currentGUIRatio)) {
            // Generate GUI event
            Logger.BPFprintln(
              "Generate GUI Event, probability : " + String.valueOf(currentGUIRatio)
            );
            generateEvents();
            isIntentEvent = false;
            GUIEventCnt += mQ.size();
          } else {
            // Generate Intent event
            Logger.BPFprintln(
              "Generate Intent Event, probability : " + String.valueOf(currentIntentRatio)
            );
            generateBPFEvent();
            IntentEventCnt += mQ.size();
            isIntentEvent = true;
          }
      } catch (StopTestingException e) {
        clearEvent();
        return null;
      }
    }
    // ====================================================================================

    mEventCount++;
    MonkeyEvent e = popEvent();
    ApeRRFormatter.logConsume(mEventConsumeLogger, e);
    return e;
  }

  /**
   * AHAFuzz: Calculates adjusted probability for GUI event generation.
   * 
   * This method dynamically adjusts the probability of generating a GUI event
   * based on the current ratio of GUI events vs Intent events, smoothly converging
   * towards the target GuiIntentEventRatio.
   * 
   * @param currentRatio Current ratio of GUI events in the total event stream
   * @return Adjusted probability for GUI event selection
   */
  private double calculateProbability(double currentRatio) {
    double adjustmentFactor = (GuiIntentEventRatio - currentRatio) / 2.0; // Adjustment factor
    return GuiIntentEventRatio + adjustmentFactor;
  }

  public Random getRandom() {
    return mRandom;
  }

  private ImageWriterQueue nextImageWriter() {
    return mImageWriters[mRandom.nextInt(mImageWriters.length)];
  }

  public boolean takeScreenshot(File screenshotFile) {
    Bitmap map = mUiAutomation.takeScreenshot();
    nextImageWriter().add(map, screenshotFile);
    return true;
  }

  public void takeScreenshot(String fileName) {
    takeScreenshot(new File(fileName));
  }

  public long getThrottle() {
    return this.mThrottle;
  }

  public Bitmap captureBitmap() {
    Bitmap map = mUiAutomation.takeScreenshot();
    return map;
  }
}
