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

exports.adminClearAccount = onCall({ region: "us-central1" }, async (request) => {
  const { db, actorUid } = await requireAdmin(request);
  const uid = request.data && request.data.uid;
  validateTargetUid(uid, actorUid);
  await requireNonAdminTarget(db, uid);

  const mappings = await db.collection("global_ids").where("uid", "==", uid).get();
  const refs = [
    db.collection("users").doc(uid),
    ...mappings.docs.map((item) => item.ref)
  ];
  try {
    for (let i = 0; i < refs.length; i += 400) {
      const batch = db.batch();
      refs.slice(i, i + 400).forEach((ref) => batch.delete(ref));
      await batch.commit();
    }
  } catch (error) {
    console.error("adminClearAccount failed", { uid, error });
    throw new HttpsError("internal", "Не удалось полностью очистить профиль и привязки Global ID.");
  }
  return { success: true, uid, deletedGlobalIdMappings: mappings.size };
});

exports.adminDeleteUser = onCall({ region: "us-central1" }, async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Требуется вход администратора.");
  }

  const db = getFirestore();
  const actorUid = request.auth.uid;
  const actorSnapshot = await db.collection("users").doc(actorUid).get();

  if (!actorSnapshot.exists || actorSnapshot.data().role !== "admin") {
    throw new HttpsError("permission-denied", "Удалять аккаунты может только администратор.");
  }

  const uid = request.data && request.data.uid;
  if (typeof uid !== "string" || !uid.trim()) {
    throw new HttpsError("invalid-argument", "Не указан UID пользователя.");
  }

  if (uid === actorUid) {
    throw new HttpsError("failed-precondition", "Нельзя удалить собственный аккаунт.");
  }

  const userRef = db.collection("users").doc(uid);
  const userSnapshot = await userRef.get();

  if (!userSnapshot.exists) {
    throw new HttpsError("not-found", "Профиль пользователя не найден в Firestore.");
  }

  if (userSnapshot.data().role === "admin") {
    throw new HttpsError("failed-precondition", "Удаление других администраторов запрещено.");
  }

  // Сначала проверяем существование Auth-пользователя, ничего не удаляя.
  try {
    await getAuth().getUser(uid);
  } catch (error) {
    if (error.code === "auth/user-not-found") {
      throw new HttpsError("not-found", "Пользователь не найден в Firebase Authentication.");
    }
    throw new HttpsError("internal", "Не удалось проверить Firebase Authentication.");
  }

  const globalIdsSnapshot = await db.collection("global_ids")
    .where("uid", "==", uid)
    .get();

  // Firebase Auth и Firestore не поддерживают общую транзакцию.
  // Удаляем Auth-пользователя, затем профиль и привязанные служебные записи.
  try {
    await getAuth().deleteUser(uid);
  } catch (error) {
    throw new HttpsError("internal", "Не удалось удалить пользователя из Firebase Authentication.");
  }

  try {
    const refs = [
      userRef,
      db.collection("employee_training").doc(uid),
      ...globalIdsSnapshot.docs.map((document) => document.ref)
    ];

    // Пакеты меньше лимита Firestore batch (500 операций).
    for (let i = 0; i < refs.length; i += 400) {
      const batch = db.batch();
      refs.slice(i, i + 400).forEach((ref) => batch.delete(ref));
      await batch.commit();
    }
  } catch (error) {
    console.error("Auth account deleted but Firestore cleanup failed", { uid, error });
    throw new HttpsError(
      "internal",
      "Пользователь удалён из Firebase Authentication, но очистка Firestore завершилась не полностью. Проверьте журнал функции."
    );
  }

  return {
    success: true,
    uid,
    deletedGlobalIdMappings: globalIdsSnapshot.size
  };
});
