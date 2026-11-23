import React, { useEffect, useState, useRef } from "react";
import { View, Text, StyleSheet, Pressable, ScrollView } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useLocalSearchParams, useRouter } from "expo-router";
import * as Location from "expo-location";
import { CameraView, useCameraPermissions } from "expo-camera";
import { Ionicons } from "@expo/vector-icons";
import { theme } from "@/src/theme";
import { Button } from "@/src/ui";
import { api } from "@/src/api/client";
import { formatShiftTime } from "@/src/utils/format";
import { success as hapticSuccess, impact as hapticImpact } from "@/src/utils/haptics";

type Step = "idle" | "locating" | "camera" | "confirming";

type AssignedShift = {
  id: string;
  start: string;
  end: string;
  status: string;
  role?: string;
  site?: { name?: string };
};

export default function TimeClock() {
  const router = useRouter();
  const { shift_id } = useLocalSearchParams<{ shift_id?: string }>();
  const [permission, requestPermission] = useCameraPermissions();
  const [active, setActive] = useState<any>(null);
  const [assignedShift, setAssignedShift] = useState<AssignedShift | null>(null);
  const [loadingShift, setLoadingShift] = useState(true);
  const [step, setStep] = useState<Step>("idle");
  const [loc, setLoc] = useState<Location.LocationObject | null>(null);
  const [selfie, setSelfie] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [locationWarning, setLocationWarning] = useState<string | null>(null);
  const [now, setNow] = useState(new Date());
  const cameraRef = useRef<CameraView | null>(null);

  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoadingShift(true);
      setError(null);
      try {
        const status: any = await api("/timeclock/status");
        if (cancelled) return;
        setActive(status.active);
        if (status.active) return;

        if (shift_id) {
          const shift: AssignedShift = await api(`/shifts/${encodeURIComponent(shift_id)}`);
          if (!cancelled) setAssignedShift(shift);
          return;
        }

        const nowMs = Date.now();
        const from = new Date(nowMs - 24 * 60 * 60 * 1000).toISOString();
        const to = new Date(nowMs + 8 * 24 * 60 * 60 * 1000).toISOString();
        const schedule: any = await api(`/schedule?start=${encodeURIComponent(from)}&end=${encodeURIComponent(to)}`);
        const eligible = (schedule.shifts || []).find((shift: AssignedShift) => {
          if (shift.status !== "scheduled") return false;
          const startMs = new Date(shift.start).getTime();
          const endMs = new Date(shift.end).getTime();
          return Number.isFinite(startMs) && Number.isFinite(endMs)
            && nowMs >= startMs - 2 * 60 * 60 * 1000
            && nowMs <= endMs + 4 * 60 * 60 * 1000;
        });
        if (!cancelled) setAssignedShift(eligible || null);
      } catch (e: any) {
        if (!cancelled) setError(e.message || "Your assigned shift could not be loaded.");
      } finally {
        if (!cancelled) setLoadingShift(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [shift_id]);

  // GPS location ping every 3 minutes while clocked in
  useEffect(() => {
    if (!active) return;
    const ping = async () => {
      try {
        const { status } = await Location.requestForegroundPermissionsAsync();
        if (status !== "granted") {
          setLocationWarning("Live location sharing is paused because location permission is unavailable.");
          return;
        }
        const l = await Location.getCurrentPositionAsync({ accuracy: Location.Accuracy.Balanced });
        await api("/timeclock/location-ping", {
          method: "POST",
          body: { latitude: l.coords.latitude, longitude: l.coords.longitude, accuracy_m: l.coords.accuracy },
        });
        setLocationWarning(null);
      } catch {
        setLocationWarning("Live location could not be updated. Check connectivity and location services.");
      }
    };
    ping(); // immediate ping on mount / clock-in
    const t = setInterval(ping, 3 * 60 * 1000);
    return () => clearInterval(t);
  }, [active]);

  const beginClockIn = async () => {
    setError(null);
    if (!assignedShift) {
      setError("No assigned shift is currently inside the allowed clock-in window.");
      return;
    }
    setStep("locating");
    try {
      const { status } = await Location.requestForegroundPermissionsAsync();
      if (status === "granted") {
        const l = await Location.getCurrentPositionAsync({ accuracy: Location.Accuracy.Balanced });
        setLoc(l);
      } else {
        setError("Location permission is required to verify the work site.");
        setStep("idle");
        return;
      }
    } catch { setError("Your location could not be verified. Try again outdoors or check location services."); setStep("idle"); return; }
    if (!permission?.granted) {
      const r = await requestPermission();
      if (!r.granted) { setError("Camera required for verification"); setStep("idle"); return; }
    }
    setStep("camera");
  };

  const captureSelfie = async () => {
    if (!cameraRef.current) return;
    try {
      const photo = await cameraRef.current.takePictureAsync({ quality: 0.4, base64: true });
      if (photo?.base64) { setSelfie(photo.base64); setStep("confirming"); }
    } catch (e: any) { setError(e.message); }
  };

  const submitClockIn = async () => {
    if (!selfie || !loc || !assignedShift) { setError("An eligible assigned shift, location, and selfie are required."); return; }
    setError(null);
    try {
      const r: any = await api("/timeclock/clock-in", {
        method: "POST",
        body: {
          shift_id: assignedShift.id, latitude: loc.coords.latitude, longitude: loc.coords.longitude,
          selfie_base64: selfie,
        },
      });
      setActive(r.entry);
      hapticSuccess();
      setStep("idle");
      setSelfie(null);
    } catch (e: any) { setError(e.message); }
  };

  const clockOut = async () => {
    setError(null);
    try {
      const { status } = await Location.requestForegroundPermissionsAsync();
      if (status !== "granted") throw new Error("Location permission is required to clock out.");
      const l = await Location.getCurrentPositionAsync({ accuracy: Location.Accuracy.Balanced });
      const latitude = l.coords.latitude; const longitude = l.coords.longitude;
      await api("/timeclock/clock-out", { method: "POST", body: { latitude, longitude } });
      hapticSuccess();
      setActive(null);
    } catch (e: any) { setError(e.message); }
  };

  const toggleBreak = async () => {
    hapticImpact();
    const onBreak = active?.breaks?.length && !active.breaks[active.breaks.length - 1].end;
    try {
      const r: any = await api("/timeclock/break", { method: "POST", body: { action: onBreak ? "end" : "start" } });
      setActive({ ...active, breaks: r.breaks });
    } catch (e: any) { setError(e.message); }
  };

  const elapsed = active ? Math.floor((now.getTime() - new Date(active.clock_in).getTime()) / 1000) : 0;
  const hh = String(Math.floor(elapsed / 3600)).padStart(2, "0");
  const mm = String(Math.floor((elapsed % 3600) / 60)).padStart(2, "0");
  const ss = String(elapsed % 60).padStart(2, "0");
  const onBreak = active?.breaks?.length && !active.breaks[active.breaks.length - 1].end;

  return (
    <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
      <View style={styles.header}>
        <Pressable testID="back-btn" onPress={() => router.back()} hitSlop={12} style={{ paddingRight: 12 }} accessibilityLabel="Go back" accessibilityRole="button">
          <Ionicons name="chevron-back" size={26} color={theme.colors.text} />
        </Pressable>
        <Text style={styles.title}>Time Clock</Text>
      </View>

      {active ? (
        <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
          <View style={styles.activeBlock}>
            <Text style={styles.activeLabel}>ON DUTY</Text>
            <Text style={styles.timer}>{hh}:{mm}:{ss}</Text>
            <Text style={styles.since}>Since {formatShiftTime(active.clock_in)}</Text>
            {active.geofence_ok === false && (
              <Text style={styles.warnText}>Outside geofence · {Math.round(active.geofence_distance_m || 0)}m from site</Text>
            )}
            {locationWarning && <Text style={styles.warnText}>{locationWarning}</Text>}
          </View>

          <View style={{ marginTop: 32, gap: 10 }}>
            <Button testID="break-btn" label={onBreak ? "End Break" : "Start Break"} variant="secondary" onPress={toggleBreak} />
            <Button testID="clock-out-btn" label="Clock Out" onPress={clockOut} />
          </View>
          {error && <Text style={styles.error}>{error}</Text>}
        </ScrollView>
      ) : step === "camera" ? (
        <View style={{ flex: 1 }}>
          <CameraView ref={cameraRef} facing="front" style={{ flex: 1 }} />
          <View style={styles.captureBar}>
            <Text style={styles.captureLabel}>Align your face in frame</Text>
            <Pressable
              testID="capture-selfie-btn"
              onPress={captureSelfie}
              style={styles.captureBtn}
              accessibilityLabel="Capture selfie"
              accessibilityRole="button"
            >
              <View style={styles.captureInner} />
            </Pressable>
          </View>
        </View>
      ) : step === "confirming" ? (
        <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
          <Text style={styles.confirmTitle}>Confirm Clock-In</Text>
          <View style={styles.confirmList}>
            <View style={styles.confirmRow}><Ionicons name="location-outline" size={18} color={theme.colors.text} /><Text style={styles.confirmText}>{loc ? `${loc.coords.latitude.toFixed(4)}, ${loc.coords.longitude.toFixed(4)}` : "GPS unavailable"}</Text></View>
            <View style={styles.confirmRow}><Ionicons name="time-outline" size={18} color={theme.colors.text} /><Text style={styles.confirmText}>{now.toLocaleString()}</Text></View>
            <View style={styles.confirmRow}><Ionicons name="camera-outline" size={18} color={theme.colors.text} /><Text style={styles.confirmText}>Selfie captured</Text></View>
          </View>
          {error && <Text style={styles.error}>{error}</Text>}
          <View style={{ marginTop: 24, gap: 10 }}>
            <Button testID="confirm-clock-in-btn" label="Clock In" onPress={submitClockIn} />
            <Button label="Retake" variant="secondary" onPress={() => setStep("camera")} />
          </View>
        </ScrollView>
      ) : (
        <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
          <View style={styles.idleBlock}>
            <Text style={styles.currentTime}>
              {String(now.getHours()).padStart(2, "0")}:{String(now.getMinutes()).padStart(2, "0")}
            </Text>
            <Text style={styles.currentDate}>{now.toDateString()}</Text>
          </View>
          {assignedShift ? (
            <View style={styles.shiftCard}>
              <Ionicons name="business-outline" size={20} color={theme.colors.text} />
              <View style={{ flex: 1 }}>
                <Text style={styles.shiftSite}>{assignedShift.site?.name || "Assigned work site"}</Text>
                <Text style={styles.shiftMeta}>
                  {assignedShift.role ? `${assignedShift.role} · ` : ""}{formatShiftTime(assignedShift.start)} – {formatShiftTime(assignedShift.end)}
                </Text>
              </View>
            </View>
          ) : !loadingShift && !error ? (
            <Text style={styles.error}>No assigned shift is currently inside the allowed clock-in window.</Text>
          ) : null}
          <Text style={styles.hint}>Location and selfie required to clock in.</Text>
          {error && <Text style={styles.error}>{error}</Text>}
          <View style={{ marginTop: 32 }}>
            <Button testID="start-clock-in-btn" label={loadingShift ? "Loading Assignment…" : "Clock In"} disabled={loadingShift || !assignedShift} onPress={beginClockIn} />
          </View>
        </ScrollView>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: theme.colors.bg },
  header: { flexDirection: "row", alignItems: "center", paddingHorizontal: 12, paddingTop: 8, paddingBottom: 12 },
  title: { color: theme.colors.text, fontSize: 20, fontWeight: "600" },
  content: { padding: 20 },
  idleBlock: { alignItems: "center", paddingVertical: 40 },
  currentTime: { color: theme.colors.text, fontSize: 72, fontWeight: "300", letterSpacing: -2, fontVariant: ["tabular-nums"] },
  currentDate: { color: theme.colors.textSecondary, fontSize: 14, marginTop: 6 },
  hint: { color: theme.colors.textSecondary, fontSize: 14, textAlign: "center" },
  shiftCard: { flexDirection: "row", alignItems: "center", gap: 12, backgroundColor: theme.colors.card, borderRadius: theme.radius.md, padding: 16, marginBottom: 18 },
  shiftSite: { color: theme.colors.text, fontSize: 15, fontWeight: "600" },
  shiftMeta: { color: theme.colors.textSecondary, fontSize: 13, marginTop: 4 },
  activeBlock: { alignItems: "center", paddingVertical: 40 },
  activeLabel: { color: theme.colors.textSecondary, fontSize: 12, letterSpacing: 0.8 },
  timer: { color: theme.colors.text, fontSize: 64, fontWeight: "300", marginTop: 12, letterSpacing: -1.5, fontVariant: ["tabular-nums"] },
  since: { color: theme.colors.textSecondary, fontSize: 14, marginTop: 8 },
  warnText: { color: theme.colors.error, fontSize: 13, marginTop: 10 },
  webCam: { flex: 1, backgroundColor: theme.colors.card, alignItems: "center", justifyContent: "center" },
  webCamText: { color: theme.colors.textSecondary, marginTop: 10 },
  captureBar: { padding: 24, alignItems: "center", backgroundColor: theme.colors.bg },
  captureLabel: { color: theme.colors.textSecondary, fontSize: 13, marginBottom: 20 },
  captureBtn: { width: 70, height: 70, borderRadius: 35, borderWidth: 3, borderColor: theme.colors.text, alignItems: "center", justifyContent: "center" },
  captureInner: { width: 56, height: 56, borderRadius: 28, backgroundColor: theme.colors.text },
  confirmTitle: { color: theme.colors.text, fontSize: 22, fontWeight: "600", marginBottom: 20 },
  confirmList: { backgroundColor: theme.colors.card, borderRadius: theme.radius.md, paddingHorizontal: 16 },
  confirmRow: { flexDirection: "row", alignItems: "center", gap: 12, paddingVertical: 14, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: theme.colors.divider },
  confirmText: { color: theme.colors.text, fontSize: 14, flex: 1 },
  error: { color: theme.colors.error, textAlign: "center", marginTop: 14, fontSize: 13 },
});
