package com.android.commands.monkey;

import android.app.ActivityManager;
import android.app.IActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.IPackageManager;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Binder;
import android.os.Bundle;
import android.os.LocaleList;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.view.IWindowManager;
import com.android.commands.monkey.ape.utils.Logger;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.TimeZone;
import org.json.*;

public class TelephonyMutation {

  public static byte[][] MessageByteArray(String action){
    String mutation_value = Mutation.getIntentRandomString(action, null);
    byte[] MessageByteArray = createMessageByteArray(mutation_value);
    byte[][] pdus = new byte[1][];
    pdus[0] = MessageByteArray;
    return pdus;
  }

  public static byte[] createMessageByteArray(
    // String phoneNumber,
    String message
  ) {
    Logger.BPFprintln("createMessageByteArray called, message : " + message);
    // Header fixed value
    byte[] header = new byte[] { 0x00, 0x00, 0x0c, (byte) 0x81 };
    // convert phone number
    byte[] phoneNumberBytes = convertPhoneNumber();
    // current time Header fixed value
    byte[] secondHeader = new byte[] { 0x00, 0x08 };
    // current time
    byte[] currentTimeBytes = getCurrentTimeBytes();
    // message string Header fixed value

    byte message_length = (byte) (
      message.getBytes(StandardCharsets.UTF_16BE).length + 4
    );

    byte[] thirdHeader = new byte[] { 0x63, message_length };
    // byte[] string_length = new byte[]
    // message start
    byte[] messageStart = new byte[] { 0x20, 0x1c };
    // message UTF-16 incoding
    byte[] messageBytes = message.getBytes(StandardCharsets.UTF_16BE);
    // message end
    byte[] messageEnd = new byte[] { 0x20, 0x1d };

    // total byte array
    ByteBuffer buffer = ByteBuffer.allocate(
      header.length +
      phoneNumberBytes.length +
      secondHeader.length +
      currentTimeBytes.length +
      thirdHeader.length +
      messageStart.length +
      messageBytes.length +
      messageEnd.length
    );
    buffer.put(header);
    buffer.put(phoneNumberBytes);
    buffer.put(secondHeader);
    buffer.put(currentTimeBytes);
    buffer.put(thirdHeader);
    buffer.put(messageStart);
    buffer.put(messageBytes);
    buffer.put(messageEnd);

    Logger.BPFprintln(
      "Generate Byte array : " + byteArrayToHex(buffer.array())
    );
    return buffer.array();
  }

  private static byte[] convertPhoneNumber() {
    // This design use determined phone number
    return new byte[] {
      (byte) 0x28,
      (byte) 0x01,
      (byte) 0x37,
      (byte) 0x65,
      (byte) 0x52,
      (byte) 0x92,
    };
  }

  private static byte[] getCurrentTimeBytes() {
    LocalDateTime now = LocalDateTime.now();
    // convert each field to string, then convert two-digit string to number and store in byte array
    String year = String.format("%02d", now.getYear() % 100);
    String month = String.format("%02d", now.getMonthValue());
    String day = String.format("%02d", now.getDayOfMonth());
    String hour = String.format("%02d", now.getHour());
    String minute = String.format("%02d", now.getMinute());
    String second = String.format("%02d", now.getSecond());
    int yearInt = Integer.parseInt(year);
    int monthInt = Integer.parseInt(month);
    int dayInt = Integer.parseInt(day);
    int hourInt = Integer.parseInt(hour);
    int minuteInt = Integer.parseInt(minute);
    int secondInt = Integer.parseInt(second);

    byte yearByte = (byte) ((yearInt / 10) + ((yearInt % 10) * 16));
    byte monthByte = (byte) ((monthInt / 10) + ((monthInt % 10) * 16));
    byte dayByte = (byte) ((dayInt / 10) + ((dayInt % 10) * 16));
    byte hourByte = (byte) ((hourInt / 10) + ((hourInt % 10) * 16));
    byte minuteByte = (byte) ((minuteInt / 10) + ((minuteInt % 10) * 16));
    byte secondByte = (byte) ((secondInt / 10) + ((secondInt % 10) * 16));

    return new byte[] {
      yearByte,
      monthByte,
      dayByte,
      hourByte,
      minuteByte,
      secondByte,
    };
  }

  public static String byteArrayToHex(byte[] a) {
    StringBuilder hexString = new StringBuilder();
    for (byte b : a) {
      hexString.append(String.format("%02x ", b));
    }
    return (hexString.toString());
  }
}
