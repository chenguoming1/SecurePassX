/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import AuthScreen from "./components/AuthScreen";
import VaultDashboard from "./components/VaultDashboard";

interface SessionData {
  userId: number;
  username: string;
  encryptionKey: CryptoKey;
  token: string;
  biometricEnabled: boolean;
}

export default function App() {
  const [session, setSession] = useState<SessionData | null>(null);

  const handleUnlockSuccess = (
    userId: number,
    username: string,
    encryptionKey: CryptoKey,
    token: string,
    biometricEnabled: boolean
  ) => {
    setSession({
      userId,
      username,
      encryptionKey,
      token,
      biometricEnabled,
    });
  };

  const handleLockSession = () => {
    setSession(null);
  };

  return (
    <div id="app-root-container" className="min-h-screen bg-[#020617] text-slate-100 font-sans antialiased overflow-x-hidden">
      <AnimatePresence mode="wait">
        {!session ? (
          <motion.div
            key="auth-view"
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.98 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="w-full h-full"
          >
            <AuthScreen onUnlockSuccess={handleUnlockSuccess} />
          </motion.div>
        ) : (
          <motion.div
            key="dashboard-view"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="w-full h-full"
          >
            <VaultDashboard
              userId={session.userId}
              username={session.username}
              encryptionKey={session.encryptionKey}
              token={session.token}
              initialBiometricEnabled={session.biometricEnabled}
              onLockSession={handleLockSession}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

