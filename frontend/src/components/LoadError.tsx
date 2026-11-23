import { Ionicons } from "@expo/vector-icons";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { theme } from "@/src/theme";

type LoadErrorProps = {
  message?: string;
  onRetry: () => void | Promise<void>;
};

export function errorMessage(error: unknown, fallback = "Unable to load this information.") {
  return error instanceof Error && error.message ? error.message : fallback;
}

export function LoadError({ message = "Unable to load this information.", onRetry }: LoadErrorProps) {
  return (
    <View style={styles.container} accessibilityRole="alert">
      <Ionicons name="cloud-offline-outline" size={36} color={theme.colors.textSecondary} />
      <Text style={styles.title}>Something went wrong</Text>
      <Text style={styles.message}>{message}</Text>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Retry loading"
        testID="retry-load"
        style={styles.button}
        onPress={onRetry}
      >
        <Text style={styles.buttonText}>Try Again</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { alignItems: "center", justifyContent: "center", paddingHorizontal: 28, paddingVertical: 56 },
  title: { color: theme.colors.text, fontSize: 18, fontWeight: "700", marginTop: 14 },
  message: { color: theme.colors.textSecondary, fontSize: 14, lineHeight: 20, textAlign: "center", marginTop: 8 },
  button: { backgroundColor: theme.colors.text, borderRadius: 10, paddingHorizontal: 22, paddingVertical: 12, marginTop: 20 },
  buttonText: { color: theme.colors.bg, fontSize: 14, fontWeight: "700" },
});
