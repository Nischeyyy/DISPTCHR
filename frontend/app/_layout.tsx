import { Stack, useRouter, useSegments } from "expo-router";
import * as SplashScreen from "expo-splash-screen";
import { useEffect } from "react";
import { Platform, View, ActivityIndicator } from "react-native";
import * as Notifications from "expo-notifications";
import { AndroidImportance } from "expo-notifications";
import Constants from "expo-constants";
import * as Linking from "expo-linking";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { GestureHandlerRootView } from "react-native-gesture-handler";

import { useIconFonts } from "@/src/hooks/use-icon-fonts";
import { AuthProvider, useAuth } from "@/src/auth/AuthContext";
import { NotificationsProvider } from "@/src/context/NotificationsContext";
import { theme } from "@/src/theme";
import { api } from "@/src/api/client";
import { ErrorBoundary } from "@/src/components/ErrorBoundary";

// Push notification module-scope setup
if (Platform.OS !== "web") {
  Notifications.setNotificationHandler({
    handleNotification: async () => ({
      shouldShowAlert: true,
      shouldPlaySound: true,
      shouldSetBadge: false,
      shouldShowBanner: true,
      shouldShowList: true,
    }) as any,
  });
}

if (Platform.OS === "android") {
  Notifications.setNotificationChannelAsync("default", {
    name: "Default",
    importance: AndroidImportance.MAX,
    sound: "default",
  });
}

SplashScreen.preventAutoHideAsync();

function AuthGate() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const segments = useSegments();

  useEffect(() => {
    if (loading) return;
    const inAuthGroup = segments[0] === "(auth)";
    const inTabsGroup = segments[0] === "(tabs)";
    if (!user && !inAuthGroup) {
      router.replace("/(auth)/login");
    } else if (user && inAuthGroup) {
      router.replace("/(tabs)");
    } else if (user && !inTabsGroup && !inAuthGroup) {
      router.replace("/(tabs)");
    }
  }, [user, loading, segments, router]);

  useEffect(() => {
    if (!user || Platform.OS === "web") return;
    (async () => {
      try {
        const { status } = await Notifications.requestPermissionsAsync();
        if (status !== "granted") return;
        const projectId = Constants.easConfig?.projectId ?? Constants.expoConfig?.extra?.eas?.projectId;
        if (!projectId) return;
        const t = await Notifications.getExpoPushTokenAsync({ projectId });
        await api("/register-push", {
          method: "POST",
          body: { user_id: user.id, platform: Platform.OS, device_token: t.data as string },
        });
      } catch {}
    })();
  }, [user]);

  if (loading) {
    return (
      <View style={{ flex: 1, backgroundColor: theme.colors.bg, alignItems: "center", justifyContent: "center" }}>
        <ActivityIndicator color={theme.colors.textSecondary} size="small" />
      </View>
    );
  }

  return (
    <View style={{ flex: 1 }}>
      <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: theme.colors.bg }, animation: "fade" }} />
    </View>
  );
}

export default function RootLayout() {
  const [loaded, error] = useIconFonts();
  const router = useRouter();

  useEffect(() => {
    if (loaded || error) SplashScreen.hideAsync();
  }, [loaded, error]);

  useEffect(() => {
    if (Platform.OS === "web") return;
    const sub = Notifications.addNotificationResponseReceivedListener((response) => {
      const data = response.notification.request.content.data || {};
      const url = data.deeplink || data.action_url;
      if (url) {
        if (typeof url === "string" && url.startsWith("http")) Linking.openURL(url);
        else router.push(url as any);
      }
    });
    Notifications.getLastNotificationResponseAsync().then((response) => {
      if (!response) return;
      const data = response.notification.request.content.data || {};
      const url = data.deeplink || data.action_url;
      if (url) {
        if (typeof url === "string" && url.startsWith("http")) Linking.openURL(url);
        else router.push(url as any);
      }
    });
    return () => sub.remove();
  }, [router]);

  if (!loaded && !error) return null;

  return (
    <ErrorBoundary>
      <GestureHandlerRootView style={{ flex: 1, backgroundColor: theme.colors.bg }}>
        <SafeAreaProvider>
          <AuthProvider>
            <NotificationsProvider>
              <StatusBar style="light" />
              <AuthGate />
            </NotificationsProvider>
          </AuthProvider>
        </SafeAreaProvider>
      </GestureHandlerRootView>
    </ErrorBoundary>
  );
}
