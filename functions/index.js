const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

initializeApp();

 
async function requireAdmin(request) {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Требуется вход администратора.");
  }
  const db = getFirestore();
  const actor = await db.collection("users").doc(request.auth.uid).get();
  if (!actor.exists || actor.data().role !== "admin") {
    throw new HttpsError("permission-denied", "Действие доступно только администратору.");
  }
  return { db, actorUid: request.auth.uid };
}

function validateTargetUid(uid, actorUid) {
  if (typeof uid !== "string" || !uid.trim()) {
    throw new HttpsError("invalid-argument", "Не указан UID пользователя.");
  }
  if (uid === actorUid) {
    throw new HttpsError("failed-precondition", "Нельзя выполнять это действие для собственного аккаунта.");
  }
}

async function requireNonAdminTarget(db, uid) {
  const ref = db.collection("users").doc(uid);
  const snapshot = await ref.get();
  if (!snapshot.exists) {
    throw new HttpsError("not-found", "Профиль пользователя не найден в users.");
  }
  if (snapshot.data().role === "admin") {
    throw new HttpsError("failed-precondition", "Нельзя выполнять это действие для аккаунтов администраторов.");
  }
  return { ref, data: snapshot.data() };
}

exports.adminSetUserPassword = onCall({ region: "us-central1" }, async (request) => {
  const { db, actorUid } = await requireAdmin(request);
  const uid = request.data && request.data.uid;
  const password = request.data && request.data.password;
  validateTargetUid(uid, actorUid);
  await requireNonAdminTarget(db, uid);
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    throw new HttpsError("invalid-argument", "Пароль должен содержать от 8 до 128 символов.");
  }
  try {
    await getAuth().updateUser(uid, { password });
  } catch (error) {
    console.error("adminSetUserPassword failed", { uid, code: error.code });
    throw new HttpsError("internal", "Firebase Authentication не смог обновить пароль.");
  }
  return { success: true, uid };
});
