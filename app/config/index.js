module.exports = {
    // Define application configuration
    appRoot: {
      env: process.env.NODE_ENV || "development",
      isProd: process.env.NODE_ENV === "production",
      host: process.env.HOST || "localhost",
      port: process.env.PORT || 3004,
      appName: process.env.APP_NAME || "current_project",
      getApiFolderName: process.env.API_FOLDER_NAME || "api",
      getAdminFolderName: process.env.ADMIN_FOLDER_NAME || "admin",
      getAuthFolderName: process.env.AUTH_FOLDER_NAME || "auth",
    },
  };