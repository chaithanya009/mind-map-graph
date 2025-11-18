export const MICROSOFT_ALLOWED_HOSTS = [
  "microsoft.com",
  "www.microsoft.com",
  "login.microsoftonline.com",
  "login-live.com",
  "login.live.com",
  "login.partner.microsoftonline.cn",
  "login.chinacloudapi.cn",
  "office.com",
  "www.office.com",
  "accounts.accesscontrol.windows.net",
  "login.microsoft.com",
  "aadcdn.msftauth.net",
  "logincdn.msauth.net",
  "acctcdn.msauth.net",
  "microsoftonline.com"
];

export interface DetectionSettings {
  enabled: boolean;
  scoreThreshold: number;
  ignoredHosts: string[];
}

export const DEFAULT_SETTINGS: DetectionSettings = {
  enabled: true,
  scoreThreshold: 3,
  ignoredHosts: []
};

