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
 */
package com.android.commands.monkey.ape.utils;

import android.util.Log;
import org.w3c.dom.Document;

public class Logger {

  private static final boolean BPFuzzOnly = false;
  private static final boolean debug = false;

  public static final String TAG = "[APE] ";

  public static void println(Object message) {
    if (BPFuzzOnly) return;
    System.out.format("[APE] %s\n", message);
  }

  public static void format(String format, Object... args) {
    if (BPFuzzOnly) return;
    System.out.format("[APE] " + format + "\n", args);
  }

  public static void dformat(String format, Object... args) {
    if (BPFuzzOnly) return;
    if (debug) System.out.format("[APE] *** DEBUG *** " + format + "\n", args);
  }

  public static void wformat(String format, Object... args) {
    if (BPFuzzOnly) return;
    System.out.format("[APE] *** WARNING *** " + format + "\n", args);
  }

  public static void iformat(String format, Object... args) {
    if (BPFuzzOnly) return;
    System.out.format("[APE] *** INFO *** " + format + "\n", args);
  }

  public static void wprintln(Object message) {
    if (BPFuzzOnly) return;
    System.out.format("[APE] *** WARNING *** %s\n", message);
  }

  public static void dprintln(Object message) {
    if (BPFuzzOnly) return;
    if (debug) System.out.format("[APE] *** DEBUG *** %s\n", message);
  }

  public static void iprintln(Object message) {
    if (BPFuzzOnly) return;
    System.out.format("[APE] *** INFO *** %s\n", message);
  }

  public static void BPFprintln(String message) {
    System.out.format("[AHAFuzz] : %s\n", message);
  }

  public static void printXml(Document document) {
    try {
      Utils.printXml(System.out, document);
      System.out.println();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static Logger out = new Logger() {
    public void println(String s) {
      if (stdout) {
        System.out.println(s);
      }
      if (logcat) {
        Log.i(TAG, s);
      }
    }
  };
  public static Logger err = new Logger() {
    public void println(String s) {
      if (stdout) {
        System.err.println(s);
      }
      if (logcat) {
        Log.w(TAG, s);
      }
    }
  };
  public static boolean stdout = true;
  public static boolean logcat = true;
}
