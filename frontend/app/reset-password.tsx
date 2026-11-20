import React, { useState } from "react";
import { SafeAreaView, StyleSheet, Text, TextInput, Pressable, View } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { api } from "@/src/api/client";

export default function ResetPassword() {
  const { token } = useLocalSearchParams<{ token?: string }>();
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [complete, setComplete] = useState(false);

  const submit = async () => {
    setError(null);
    if (!token) return setError("This reset link is incomplete. Request a new link.");
    if (password.length < 12) return setError("Use at least 12 characters.");
    if (password !== confirmation) return setError("The passwords do not match.");
    setBusy(true);
    try {
      await api('/auth/reset-password', {
        method: 'POST',
        body: { token, new_password: password },
        auth: false,
      });
      setComplete(true);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SafeAreaView style={styles.safe}>
      <View style={styles.card}>
        <Text style={styles.title}>Reset Password</Text>
        {complete ? (
          <>
            <Text style={styles.body}>Your password has been changed. You can now sign in.</Text>
            <Pressable style={styles.button} onPress={() => router.replace('/(auth)/login')}>
              <Text style={styles.buttonText}>Return to Sign In</Text>
            </Pressable>
          </>
        ) : (
          <>
            <Text style={styles.body}>Choose a new password for your guard account.</Text>
            <TextInput style={styles.input} secureTextEntry value={password} onChangeText={setPassword} placeholder="New password" autoCapitalize="none" />
            <TextInput style={styles.input} secureTextEntry value={confirmation} onChangeText={setConfirmation} placeholder="Confirm password" autoCapitalize="none" />
            {error && <Text style={styles.error}>{error}</Text>}
            <Pressable style={[styles.button, busy && styles.disabled]} disabled={busy} onPress={submit}>
              <Text style={styles.buttonText}>{busy ? "Updating…" : "Update Password"}</Text>
            </Pressable>
          </>
        )}
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#F2F2F7", justifyContent: "center", padding: 24 },
  card: { backgroundColor: "white", borderRadius: 18, padding: 24, gap: 14 },
  title: { fontSize: 27, fontWeight: "700", color: "#111" },
  body: { fontSize: 15, lineHeight: 22, color: "#5B5B60" },
  input: { backgroundColor: "#F2F2F7", borderRadius: 12, paddingHorizontal: 15, paddingVertical: 14, fontSize: 16 },
  error: { color: "#C62828", fontSize: 13 },
  button: { backgroundColor: "#111", borderRadius: 12, minHeight: 52, alignItems: "center", justifyContent: "center", marginTop: 4 },
  disabled: { opacity: 0.55 },
  buttonText: { color: "white", fontSize: 16, fontWeight: "600" },
});
