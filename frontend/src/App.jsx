import { useEffect, useMemo, useState } from "react";
import {
  ShieldCheck,
  Search,
  AlertTriangle,
  BookOpen,
  Brain,
  ChevronRight,
  CheckCircle2,
  XCircle,
  RotateCcw,
  BarChart3,
  Activity,
  FileWarning,
  Target,
  LockKeyhole,
  Globe,
  Smartphone,
  Cloud,
  Bug,
  Network,
  GraduationCap,
  ClipboardCheck,
} from "lucide-react";

const API= "https://cyber-threat-intelligence-api-ixtl.onrender.com";
const REQUEST_TIMEOUT = 5000;

/* =========================================================
   AWARENESS MODULES
========================================================= */

const awarenessModules = [
  {
    id: "phishing",
    title: "Phishing Awareness",
    icon: "🎣",
    summary:
      "Recognize suspicious messages, links, attachments, and impersonation attempts.",
    points: [
      "Check sender addresses and domains carefully.",
      "Do not open unexpected attachments or links.",
      "Verify urgent requests through a trusted channel.",
      "Report suspicious messages using the approved process.",
    ],
  },
  {
    id: "passwords",
    title: "Password & MFA Security",
    icon: "🔐",
    summary:
      "Protect accounts with unique passwords and multi-factor authentication.",
    points: [
      "Use a unique password for every important account.",
      "Use a password manager where permitted.",
      "Enable MFA for email, cloud, and other important accounts.",
      "Never share verification codes with another person.",
    ],
  },
  {
    id: "browsing",
    title: "Safe Browsing",
    icon: "🌐",
    summary:
      "Reduce web-based risks by checking context before interacting.",
    points: [
      "Confirm the domain before entering credentials.",
      "Be cautious with unexpected downloads.",
      "Keep browsers and extensions updated.",
      "Use trusted bookmarks for frequently used services.",
    ],
  },
  {
    id: "ransomware",
    title: "Ransomware Awareness",
    icon: "🦠",
    summary:
      "Understand prevention and safe reporting of ransomware incidents.",
    points: [
      "Maintain appropriate backups according to policy.",
      "Install trusted security updates promptly.",
      "Report unusual file-access or encryption behavior.",
      "Do not attempt destructive remediation on your own.",
    ],
  },
  {
    id: "social",
    title: "Social Engineering",
    icon: "🧠",
    summary:
      "Recognize manipulation techniques involving urgency, trust, and authority.",
    points: [
      "Treat unusual urgency as a reason to verify.",
      "Verify identity before sharing sensitive information.",
      "Be careful with requests involving payments or credentials.",
      "Escalate suspicious requests through approved channels.",
    ],
  },
  {
    id: "wifi",
    title: "Secure Wi-Fi",
    icon: "📡",
    summary:
      "Use safer practices on home, campus, and public networks.",
    points: [
      "Prefer trusted networks for sensitive work.",
      "Avoid sharing network credentials unnecessarily.",
      "Keep router firmware updated when you manage the device.",
      "Use organization-approved secure access methods when required.",
    ],
  },
  {
    id: "mobile",
    title: "Mobile Security",
    icon: "📱",
    summary:
      "Protect phones and tablets containing accounts and sensitive data.",
    points: [
      "Keep the operating system and apps updated.",
      "Use a screen lock and device security features.",
      "Install apps only from trusted sources.",
      "Review application permissions periodically.",
    ],
  },
  {
    id: "cloud",
    title: "Cloud Account Security",
    icon: "☁️",
    summary:
      "Protect cloud identities, files, and collaboration environments.",
    points: [
      "Use MFA for cloud accounts.",
      "Review sharing permissions before exposing files.",
      "Avoid public links for sensitive documents.",
      "Remove access that is no longer needed.",
    ],
  },
  {
    id: "ai",
    title: "AI-Enabled Scam Awareness",
    icon: "🤖",
    summary:
      "Understand how convincing AI-generated messages can affect security.",
    points: [
      "Do not trust a message simply because it sounds polished.",
      "Verify unusual requests independently.",
      "Use known contact details rather than replying to suspicious messages.",
      "Report suspected impersonation attempts.",
    ],
  },
  {
    id: "updates",
    title: "Updates & Vulnerabilities",
    icon: "🛡️",
    summary:
      "Reduce exposure by keeping software and systems maintained.",
    points: [
      "Apply trusted security updates according to policy.",
      "Prioritize high-risk vulnerabilities affecting your environment.",
      "Remove unsupported software where possible.",
      "Document remediation and exceptions.",
    ],
  },
  {
    id: "usb",
    title: "USB & Removable Media",
    icon: "💾",
    summary:
      "Handle removable storage carefully to reduce security risks.",
    points: [
      "Use organization-approved removable media.",
      "Do not connect unknown devices to protected systems.",
      "Use approved security controls when scanning media.",
      "Report unknown or lost media.",
    ],
  },
  {
    id: "reporting",
    title: "Incident Reporting",
    icon: "🚨",
    summary:
      "Know what to report and why early reporting matters.",
    points: [
      "Report suspicious activity promptly.",
      "Preserve relevant information instead of deleting it.",
      "Use the organization's approved reporting channel.",
      "Avoid investigation beyond your authorization.",
    ],
  },
];

/* =========================================================
   30 QUESTION SECURITY AWARENESS QUIZ
========================================================= */

const quizQuestions = [
  {
    q: "A message says your account will be disabled in 10 minutes unless you click a link. What should you do first?",
    options: [
      "Click immediately",
      "Verify the request through a trusted channel",
      "Forward it to everyone",
      "Reply with your password",
    ],
    answer: 1,
  },
  {
    q: "Which password practice is safest?",
    options: [
      "Reuse one strong password everywhere",
      "Use unique passwords for important accounts",
      "Share passwords with teammates",
      "Use your name and birth year",
    ],
    answer: 1,
  },
  {
    q: "What is the main purpose of MFA?",
    options: [
      "Make passwords shorter",
      "Add another verification factor",
      "Disable account logging",
      "Increase internet speed",
    ],
    answer: 1,
  },
  {
    q: "Before entering credentials on a website, what should you check?",
    options: [
      "Only the page color",
      "The domain and context",
      "Number of images",
      "Browser window size",
    ],
    answer: 1,
  },
  {
    q: "You receive an unexpected attachment from an unknown sender. What is safest?",
    options: [
      "Open it quickly",
      "Save it to a USB drive",
      "Do not open it and report it",
      "Send it to a friend",
    ],
    answer: 2,
  },
  {
    q: "Why should software security updates be applied?",
    options: [
      "They can address known security weaknesses",
      "They always add games",
      "They remove all security controls",
      "They make passwords unnecessary",
    ],
    answer: 0,
  },
  {
    q: "Which is an example of social engineering?",
    options: [
      "Manipulating a person into revealing sensitive information",
      "Increasing disk space",
      "Updating a browser",
      "Backing up a file",
    ],
    answer: 0,
  },
  {
    q: "What should you do with an unusual request to transfer money urgently?",
    options: [
      "Complete it immediately",
      "Verify the request using a trusted channel",
      "Post it publicly",
      "Ignore all procedures",
    ],
    answer: 1,
  },
  {
    q: "Which practice improves cloud account security?",
    options: [
      "Disable MFA",
      "Use public sharing for sensitive files",
      "Review permissions and use MFA",
      "Share one account among users",
    ],
    answer: 2,
  },
  {
    q: "What is a safer approach on public Wi-Fi?",
    options: [
      "Use trusted secure access methods for sensitive work",
      "Disable device security",
      "Share passwords over chat",
      "Install unknown certificates",
    ],
    answer: 0,
  },
  {
    q: "What should you do if you suspect a phishing message?",
    options: [
      "Report it using the approved security process",
      "Reply with credentials",
      "Delete all evidence immediately",
      "Download its attachment",
    ],
    answer: 0,
  },
  {
    q: "Why are unique passwords useful?",
    options: [
      "A compromised password is less likely to expose other accounts",
      "They remove the need for MFA",
      "They prevent every type of attack",
      "They make devices faster",
    ],
    answer: 0,
  },
  {
    q: "What should you do when an app requests unnecessary permissions?",
    options: [
      "Review and deny permissions that are not needed",
      "Grant everything automatically",
      "Share the request publicly",
      "Disable device security",
    ],
    answer: 0,
  },
  {
    q: "Which is a good ransomware prevention practice?",
    options: [
      "Maintain appropriate backups and apply updates",
      "Disable backups",
      "Open unknown attachments",
      "Ignore unusual file activity",
    ],
    answer: 0,
  },
  {
    q: "An AI-generated message looks perfectly written. Does that prove it is legitimate?",
    options: [
      "Yes",
      "No, verify the request independently",
      "Only if it has a logo",
      "Only if it uses formal language",
    ],
    answer: 1,
  },
  {
    q: "What is the safest response to an unknown USB device?",
    options: [
      "Connect it to a protected computer",
      "Use it immediately",
      "Follow policy and do not connect unknown media",
      "Give it to another user",
    ],
    answer: 2,
  },
  {
    q: "Why is early incident reporting important?",
    options: [
      "It can help defenders investigate and respond sooner",
      "It guarantees no incident occurred",
      "It removes all logs",
      "It makes passwords public",
    ],
    answer: 0,
  },
  {
    q: "What is an appropriate action when you notice suspicious activity?",
    options: [
      "Stay within your authorization and report it",
      "Probe unrelated systems",
      "Run unknown tools",
      "Attempt destructive remediation",
    ],
    answer: 0,
  },
  {
    q: "What does a risk score represent in a security dashboard?",
    options: [
      "A calculated level of concern based on selected evidence",
      "Proof that an attack occurred",
      "A legal verdict",
      "A guaranteed future event",
    ],
    answer: 0,
  },
  {
    q: "What does confidence describe?",
    options: [
      "The quality or strength of evidence supporting an assessment",
      "The size of a file",
      "Internet speed",
      "Password length",
    ],
    answer: 0,
  },
  {
    q: "An IOC appearing in a threat dataset automatically means the system is compromised.",
    options: ["True", "False"],
    answer: 1,
  },
  {
    q: "What is a good approach to suspicious links?",
    options: [
      "Use trusted channels to verify the destination",
      "Click them to see where they go",
      "Send them to a public forum",
      "Disable browser security",
    ],
    answer: 0,
  },
  {
    q: "Which account should receive strong protection?",
    options: [
      "Only social media",
      "Email and other important accounts",
      "Only guest accounts",
      "No accounts",
    ],
    answer: 1,
  },
  {
    q: "What should happen to access that is no longer required?",
    options: [
      "It should be reviewed and removed according to policy",
      "It should remain forever",
      "It should be shared",
      "It should be made public",
    ],
    answer: 0,
  },
  {
    q: "Which is safer for sensitive documents?",
    options: [
      "Approved storage with controlled sharing",
      "Public links",
      "Unknown file-sharing sites",
      "Personal accounts without authorization",
    ],
    answer: 0,
  },
  {
    q: "What is the purpose of security awareness training?",
    options: [
      "Help people recognize and respond safely to common risks",
      "Teach people to attack systems",
      "Remove all security controls",
      "Guarantee zero incidents",
    ],
    answer: 0,
  },
  {
    q: "If you receive a suspicious call requesting a verification code, what should you do?",
    options: [
      "Provide the code",
      "Verify the caller independently and do not share the code",
      "Post the code online",
      "Forward the code",
    ],
    answer: 1,
  },
  {
    q: "Why should unsupported software be avoided?",
    options: [
      "It may no longer receive security fixes",
      "It is always faster",
      "It guarantees encryption",
      "It removes vulnerabilities",
    ],
    answer: 0,
  },
  {
    q: "What is the best response to a suspected account compromise?",
    options: [
      "Use the approved incident-reporting and account-security process",
      "Delete all records",
      "Investigate unrelated accounts",
      "Share the password",
    ],
    answer: 0,
  },
  {
    q: "Which statement best describes defensive threat intelligence?",
    options: [
      "Evidence and context used to support security decisions",
      "A guarantee that every indicator is malicious",
      "A replacement for all security controls",
      "A method for attacking systems",
    ],
    answer: 0,
  },
];

/* =========================================================
   HELPERS
========================================================= */

function scoreLabel(score) {
  if (score >= 81) return "Strong";
  if (score >= 61) return "Good";
  if (score >= 41) return "Basic";
  return "Needs Improvement";
}

/* =========================================================
   MAIN APP
========================================================= */

export default function App() {
  const [tab, setTab] = useState("dashboard");

  const [stats, setStats] = useState(null);
  const [trends, setTrends] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [attack, setAttack] = useState(null);

  const [ioc, setIoc] = useState("");
  const [iocResult, setIocResult] = useState(null);

  const [apiWarning, setApiWarning] = useState(false);

  const [selectedModule, setSelectedModule] = useState(null);

  const [quizStarted, setQuizStarted] = useState(false);
  const [quizIndex, setQuizIndex] = useState(0);
  const [answers, setAnswers] = useState([]);
  const [quizResult, setQuizResult] = useState(null);

  /* ---------------- API ---------------- */

  const load = async (path, setter) => {
    const controller = new AbortController();

    const timer = setTimeout(() => {
      controller.abort();
    }, REQUEST_TIMEOUT);

    try {
      const response = await fetch(API + path, {
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.json();

      setter(data);

      return true;
    } catch (error) {
      setApiWarning(true);
      return false;
    } finally {
      clearTimeout(timer);
    }
  };

  useEffect(() => {
    load("/api/dashboard/stats", setStats);

    load("/api/dashboard/trends", (data) => {
      setTrends(data?.trends || data || []);
    });

    load("/api/alerts?limit=10", (data) => {
      setAlerts(data?.alerts || []);
    });

    load("/api/vulnerabilities", (data) => {
      setVulns(data?.vulnerabilities || data || []);
    });

    load("/api/attack/summary", setAttack);
  }, []);

  /* ---------------- IOC SEARCH ---------------- */

  const searchIOC = async () => {
    if (!ioc.trim()) return;

    const success = await load(
      "/api/indicators/search?indicator=" +
        encodeURIComponent(ioc.trim()),
      setIocResult
    );

    if (!success) {
      setIocResult({
        found: false,
        error: "Unable to reach the IOC search service.",
      });
    }
  };

  /* ---------------- QUIZ ---------------- */

  const startQuiz = () => {
    setQuizStarted(true);
    setQuizIndex(0);
    setAnswers([]);
    setQuizResult(null);
  };

  const answerQuestion = (choice) => {
    const nextAnswers = [...answers, choice];

    if (quizIndex < quizQuestions.length - 1) {
      setAnswers(nextAnswers);
      setQuizIndex(quizIndex + 1);
      return;
    }

    const correct = nextAnswers.reduce(
      (total, answer, index) =>
        total + (answer === quizQuestions[index].answer ? 1 : 0),
      0
    );

    const score = Math.round((correct / quizQuestions.length) * 100);

    setAnswers(nextAnswers);

    setQuizResult({
      correct,
      score,
      label: scoreLabel(score),
    });
  };

  const resetQuiz = () => {
    setQuizStarted(false);
    setQuizIndex(0);
    setAnswers([]);
    setQuizResult(null);
  };

  /* ---------------- DATA ---------------- */

  const severityData = useMemo(() => {
    const rows =
      stats?.severity_distribution ||
      stats?.severityDistribution ||
      {};

    return Object.entries(rows);
  }, [stats]);

  const categoryData = useMemo(() => {
    const rows =
      stats?.category_distribution ||
      stats?.threat_category_distribution ||
      {};

    return Object.entries(rows)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [stats]);

  /* ---------------- NAVIGATION ---------------- */

  const nav = [
    ["dashboard", "Dashboard", BarChart3],
    ["investigate", "IOC Investigation", Search],
    ["awareness", "Awareness Center", BookOpen],
    ["quiz", "Security Quiz", Brain],
    ["executive", "Executive Summary", Target],
    ["soc", "SOC Workflow", Network],
  ];

  return (
    <div className="app">
      <style>{`
        * {
          box-sizing: border-box;
        }

        body {
          margin: 0;
          font-family: Inter, Segoe UI, Arial, sans-serif;
          background: #07111f;
          color: #e5edf7;
        }

        button,
        input {
          font: inherit;
        }

        button {
          cursor: pointer;
        }

        .app {
          min-height: 100vh;
          background:
            radial-gradient(
              circle at 20% 0%,
              #12243b 0,
              #07111f 42%,
              #050b14 100%
            );
        }

        .top {
          height: 72px;
          border-bottom: 1px solid #203149;
          background: rgba(5, 12, 23, 0.95);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 28px;
          position: sticky;
          top: 0;
          z-index: 10;
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 12px;
          font-weight: 800;
        }

        .brandIcon {
          width: 40px;
          height: 40px;
          border-radius: 11px;
          background: #102a46;
          display: grid;
          place-items: center;
          color: #4ade80;
        }

        .brand small {
          display: block;
          color: #7890aa;
          font-size: 10px;
          letter-spacing: 1.4px;
          margin-top: 2px;
        }

        .mode {
          font-size: 11px;
          color: #4ade80;
          border: 1px solid #24563b;
          padding: 7px 10px;
          border-radius: 20px;
        }

        .layout {
          display: flex;
          min-height: calc(100vh - 72px);
        }

        .side {
          width: 245px;
          border-right: 1px solid #203149;
          padding: 22px 14px;
          background: rgba(5, 13, 24, 0.65);
        }

        .navTitle {
          color: #50657d;
          font-size: 10px;
          font-weight: 800;
          letter-spacing: 1.4px;
          padding: 5px 14px 10px;
        }

        .navbtn {
          width: 100%;
          border: 0;
          background: transparent;
          color: #8fa3ba;
          text-align: left;
          padding: 12px 14px;
          border-radius: 9px;
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 5px;
        }

        .navbtn:hover,
        .navbtn.active {
          background: #102238;
          color: #ffffff;
        }

        .content {
          flex: 1;
          padding: 28px;
          max-width: 1500px;
          margin: auto;
          width: 100%;
        }

        h1 {
          margin: 0;
          font-size: 28px;
        }

        h2 {
          margin-top: 0;
        }

        .subtitle {
          color: #8196ae;
          margin: 7px 0 25px;
        }

        .sectionTitle {
          font-size: 17px;
          margin: 30px 0 14px;
        }

        .warning {
          padding: 11px 14px;
          border: 1px solid #674c18;
          background: #241c0b;
          color: #facc15;
          border-radius: 9px;
          margin-bottom: 18px;
          font-size: 13px;
        }

        .cards {
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          gap: 13px;
        }

        .card {
          background: #0b1829;
          border: 1px solid #1e3047;
          border-radius: 12px;
          padding: 18px;
        }

        .label {
          font-size: 11px;
          color: #7288a1;
          text-transform: uppercase;
          letter-spacing: 1px;
        }

        .value {
          font-size: 27px;
          font-weight: 800;
          margin-top: 9px;
        }

        .grid2 {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 15px;
        }

        .grid3 {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 15px;
        }

        .panel {
          background: #0b1829;
          border: 1px solid #1e3047;
          border-radius: 12px;
          padding: 18px;
        }

        .panel h3 {
          margin: 0 0 14px;
          font-size: 15px;
        }

        .bars .barrow {
          margin: 10px 0;
        }

        .barhead {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
          color: #a9b8ca;
        }

        .bar {
          height: 7px;
          background: #15263b;
          border-radius: 10px;
          overflow: hidden;
          margin-top: 5px;
        }

        .fill {
          height: 100%;
          background: #38bdf8;
          border-radius: 10px;
        }

        .search {
          display: flex;
          gap: 9px;
          margin-bottom: 16px;
        }

        .search input {
          flex: 1;
          background: #07111f;
          border: 1px solid #29405b;
          color: #fff;
          padding: 12px;
          border-radius: 8px;
          outline: none;
        }

        .search input:focus {
          border-color: #3b82f6;
        }

        .primary {
          background: #2563eb;
          border: 0;
          color: #fff;
          padding: 11px 16px;
          border-radius: 8px;
          font-weight: 700;
          display: inline-flex;
          align-items: center;
          gap: 7px;
        }

        .primary:hover {
          background: #1d4ed8;
        }

        .secondary {
          background: #15263b;
          border: 1px solid #29405b;
          color: #d8e3ef;
          padding: 10px 14px;
          border-radius: 8px;
          display: inline-flex;
          align-items: center;
          gap: 7px;
        }

        .iocbox {
          background: #07111f;
          border: 1px solid #203149;
          border-radius: 9px;
          padding: 15px;
        }

        .found {
          color: #4ade80;
        }

        .notfound {
          color: #f59e0b;
        }

        .mono {
          font-family: Consolas, monospace;
          color: #b9d6ef;
        }

        .tag {
          display: inline-block;
          padding: 4px 7px;
          border-radius: 5px;
          background: #172a40;
          font-size: 10px;
          margin: 2px;
        }

        .empty {
          color: #71869d;
          padding: 20px;
          text-align: center;
        }

        .moduleGrid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 14px;
        }

        .module {
          cursor: pointer;
          transition: 0.15s;
        }

        .module:hover {
          transform: translateY(-2px);
          border-color: #37618d;
        }

        .moduleIcon {
          font-size: 30px;
        }

        .module h3 {
          margin: 9px 0 6px;
        }

        .module p {
          color: #879bb1;
          font-size: 13px;
          line-height: 1.5;
          margin: 0;
        }

        .moduleDetail {
          margin-top: 18px;
        }

        .points {
          padding-left: 20px;
          color: #aebdcd;
          line-height: 1.8;
        }

        .points li {
          margin: 5px 0;
        }

        .lessonBadge {
          display: inline-block;
          color: #60a5fa;
          font-size: 12px;
          margin-top: 12px;
        }

        .quizTop {
          display: flex;
          justify-content: space-between;
          color: #91a4ba;
          font-size: 13px;
          margin-bottom: 12px;
        }

        .question {
          font-size: 20px;
          line-height: 1.5;
          margin: 22px 0;
        }

        .option {
          width: 100%;
          text-align: left;
          background: #0c1a2c;
          border: 1px solid #263d58;
          color: #dce7f2;
          padding: 14px;
          border-radius: 9px;
          margin: 7px 0;
        }

        .option:hover {
          border-color: #3b82f6;
          background: #10243b;
        }

        .result {
          text-align: center;
          padding: 35px;
        }

        .score {
          font-size: 54px;
          font-weight: 900;
          color: #4ade80;
        }

        .result h2 {
          margin: 8px 0;
        }

        .rec {
          margin: 20px auto;
          max-width: 650px;
          text-align: left;
          background: #101f31;
          border: 1px solid #263d58;
          padding: 16px;
          border-radius: 10px;
        }

        .workflow {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          justify-content: center;
          gap: 10px;
          margin-top: 20px;
        }

        .workflowStep {
          background: #102238;
          border: 1px solid #29405b;
          padding: 16px;
          border-radius: 10px;
          min-width: 145px;
          text-align: center;
        }

        .workflowStep b {
          display: block;
          margin-top: 7px;
          font-size: 13px;
        }

        .workflowArrow {
          color: #4b6b8c;
        }

        .summaryBox {
          background: linear-gradient(135deg, #0e2238, #0b1829);
          border: 1px solid #29405b;
          border-radius: 12px;
          padding: 22px;
          margin-bottom: 15px;
        }

        .summaryIcon {
          width: 42px;
          height: 42px;
          border-radius: 10px;
          background: #102a46;
          display: grid;
          place-items: center;
          color: #60a5fa;
          margin-bottom: 12px;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          font-size: 12px;
        }

        th,
        td {
          text-align: left;
          padding: 11px 8px;
          border-bottom: 1px solid #1d2d42;
        }

        th {
          color: #7288a1;
          text-transform: uppercase;
          font-size: 10px;
        }

        td {
          color: #b8c6d6;
        }

        footer {
          margin-top: 35px;
          padding: 20px 0;
          color: #60748b;
          font-size: 11px;
          border-top: 1px solid #17283d;
        }

        @media (max-width: 1100px) {
          .cards {
            grid-template-columns: repeat(3, 1fr);
          }

          .moduleGrid {
            grid-template-columns: repeat(2, 1fr);
          }
        }

        @media (max-width: 760px) {
          .side {
            width: 65px;
            padding: 15px 8px;
          }

          .navbtn span,
          .navTitle {
            display: none;
          }

          .content {
            padding: 18px;
          }

          .cards,
          .grid2,
          .grid3,
          .moduleGrid {
            grid-template-columns: 1fr;
          }

          .mode {
            display: none;
          }

          .search {
            flex-direction: column;
          }
        }
      `}</style>

      {/* HEADER */}

      <header className="top">
        <div className="brand">
          <div className="brandIcon">
            <ShieldCheck size={23} />
          </div>

          <div>
            ThreatGuard
            <small>SECURITY OPERATIONS CENTER</small>
          </div>
        </div>

        <div className="mode">DEFENSIVE ANALYSIS MODE</div>
      </header>

      <div className="layout">
        {/* SIDEBAR */}

        <aside className="side">
          <div className="navTitle">SECURITY PLATFORM</div>

          {nav.map(([id, label, Icon]) => (
            <button
              key={id}
              className={`navbtn ${tab === id ? "active" : ""}`}
              onClick={() => setTab(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </aside>

        {/* MAIN CONTENT */}

        <main className="content">
          {apiWarning && (
            <div className="warning">
              <AlertTriangle
                size={15}
                style={{
                  verticalAlign: "middle",
                  marginRight: 7,
                }}
              />
              Some API services could not respond. The dashboard remains
              available using the data that successfully loaded.
            </div>
          )}

          {/* DASHBOARD */}

          {tab === "dashboard" && (
            <Dashboard
              stats={stats}
              severityData={severityData}
              categoryData={categoryData}
              alerts={alerts}
              attack={attack}
              vulns={vulns}
            />
          )}

          {/* IOC INVESTIGATION */}

          {tab === "investigate" && (
            <IOCInvestigation
              ioc={ioc}
              setIoc={setIoc}
              iocResult={iocResult}
              searchIOC={searchIOC}
            />
          )}

          {/* AWARENESS CENTER */}

          {tab === "awareness" && (
            <AwarenessCenter
              selectedModule={selectedModule}
              setSelectedModule={setSelectedModule}
              setTab={setTab}
            />
          )}

          {/* QUIZ */}

          {tab === "quiz" && (
            <SecurityQuiz
              started={quizStarted}
              startQuiz={startQuiz}
              quizIndex={quizIndex}
              quizResult={quizResult}
              answerQuestion={answerQuestion}
              resetQuiz={resetQuiz}
            />
          )}

          {/* EXECUTIVE SUMMARY */}

          {tab === "executive" && (
            <ExecutiveSummary
              stats={stats}
              severityData={severityData}
              categoryData={categoryData}
              vulns={vulns}
              alerts={alerts}
            />
          )}

          {/* SOC WORKFLOW */}

          {tab === "soc" && <SOCWorkflow />}

          <footer>
            ThreatGuard is an educational defensive cybersecurity project
            using synthetic/local data. Dataset matches, risk scores,
            correlations, alerts, and ATT&CK context do not by themselves
            prove compromise, attribution, or malicious intent.
          </footer>
        </main>
      </div>
    </div>
  );
}

/* =========================================================
   DASHBOARD
========================================================= */

function Dashboard({
  stats,
  severityData,
  categoryData,
  alerts,
  attack,
  vulns,
}) {
  const total =
    stats?.total_threats ??
    stats?.total_records ??
    stats?.total ??
    "—";

  const unique =
    stats?.unique_indicators ??
    stats?.uniqueIndicators ??
    "—";

  const critical =
    stats?.critical_count ??
    severityData.find((x) => x[0] === "CRITICAL")?.[1] ??
    "—";

  const high =
    stats?.high_count ??
    severityData.find((x) => x[0] === "HIGH")?.[1] ??
    "—";

  const avg =
    stats?.average_risk ??
    stats?.avg_risk ??
    "—";

  const maxSeverity = Math.max(
    ...severityData.map((x) => Number(x[1])),
    1
  );

  const maxCategory = Math.max(
    ...categoryData.map((x) => Number(x[1])),
    1
  );

  return (
    <div>
      <h1>Threat Intelligence Dashboard</h1>

      <p className="subtitle">
        Analyze synthetic threat intelligence, indicators, risk,
        confidence, alerts, vulnerabilities, and ATT&CK context.
      </p>

      <div className="cards">
        <MetricCard title="Threat Records" value={total} />
        <MetricCard title="Unique Indicators" value={unique} />
        <MetricCard title="Critical" value={critical} />
        <MetricCard title="High" value={high} />
        <MetricCard
          title="Average Risk"
          value={typeof avg === "number" ? avg.toFixed(1) : avg}
        />
      </div>

      <h2 className="sectionTitle">Threat Landscape</h2>

      <div className="grid2">
        <div className="panel bars">
          <h3>Severity Distribution</h3>

          {severityData.length ? (
            severityData.map(([key, value]) => (
              <div className="barrow" key={key}>
                <div className="barhead">
                  <span>{key}</span>
                  <b>{value}</b>
                </div>

                <div className="bar">
                  <div
                    className="fill"
                    style={{
                      width:
                        (Number(value) / maxSeverity) * 100 + "%",
                    }}
                  />
                </div>
              </div>
            ))
          ) : (
            <div className="empty">No severity data available.</div>
          )}
        </div>

        <div className="panel bars">
          <h3>Top Threat Categories</h3>

          {categoryData.length ? (
            categoryData.map(([key, value]) => (
              <div className="barrow" key={key}>
                <div className="barhead">
                  <span>{key}</span>
                  <b>{value}</b>
                </div>

                <div className="bar">
                  <div
                    className="fill"
                    style={{
                      width:
                        (Number(value) / maxCategory) * 100 + "%",
                    }}
                  />
                </div>
              </div>
            ))
          ) : (
            <div className="empty">No category data available.</div>
          )}
        </div>
      </div>

      <h2 className="sectionTitle">Security Intelligence</h2>

      <div className="grid3">
        <div className="panel">
          <h3>
            <Activity size={16} /> ATT&CK Context
          </h3>

          {attack ? (
            <>
              <p>
                <b>
                  {attack.total_records ??
                    attack.total_threats ??
                    "—"}
                </b>{" "}
                records with available context.
              </p>

              <div>
                {Object.entries(
                  attack.tactics ||
                    attack.tactic_distribution ||
                    {}
                )
                  .slice(0, 6)
                  .map(([key, value]) => (
                    <span className="tag" key={key}>
                      {key}: {value}
                    </span>
                  ))}
              </div>

              <small style={{ color: "#71869d" }}>
                Demonstration context only. It does not prove attribution
                or compromise.
              </small>
            </>
          ) : (
            <div className="empty">Loading ATT&CK summary...</div>
          )}
        </div>

        <div className="panel">
          <h3>
            <Bug size={16} /> Vulnerability Awareness
          </h3>

          <p>
            <b>{Array.isArray(vulns) ? vulns.length : "—"}</b>{" "}
            vulnerability observations available.
          </p>

          <p style={{ color: "#9fb0c3" }}>
            Review synthetic CVE-style observations by severity and
            priority.
          </p>
        </div>

        <div className="panel">
          <h3>
            <AlertTriangle size={16} /> Alert Monitoring
          </h3>

          <p>
            <b>{alerts?.length ?? 0}</b> recent alerts loaded.
          </p>

          <p style={{ color: "#9fb0c3" }}>
            Alerts support defensive triage and do not automatically
            confirm compromise.
          </p>
        </div>
      </div>

      <h2 className="sectionTitle">Recent Security Alerts</h2>

      <div className="panel">
        {alerts?.length ? (
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Indicator</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={
                    alert.alert_id ||
                    alert.threat_id ||
                    Math.random()
                  }
                >
                  <td>{alert.alert_id || "—"}</td>
                  <td>{alert.severity || "—"}</td>
                  <td>{alert.risk_score ?? "—"}</td>
                  <td className="mono">
                    {alert.indicator || "—"}
                  </td>
                  <td>{alert.status || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty">
            Alerts are still loading or unavailable.
          </div>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   METRIC CARD
========================================================= */

function MetricCard({ title, value }) {
  return (
    <div className="card">
      <div className="label">{title}</div>
      <div className="value">{value}</div>
    </div>
  );
}

/* =========================================================
   IOC INVESTIGATION
========================================================= */

function IOCInvestigation({
  ioc,
  setIoc,
  iocResult,
  searchIOC,
}) {
  return (
    <div>
      <h1>IOC Investigation</h1>

      <p className="subtitle">
        Validate and investigate indicators using the local synthetic
        defensive dataset.
      </p>

      <div className="panel">
        <div className="search">
          <input
            value={ioc}
            onChange={(event) => setIoc(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                searchIOC();
              }
            }}
            placeholder="Try 203.0.113.250 or CVE-2026-1005"
          />

          <button className="primary" onClick={searchIOC}>
            <Search size={16} />
            Search
          </button>
        </div>

        {!iocResult && (
          <div className="empty">
            Enter an IP, domain, URL, hash, email/sender domain,
            or CVE ID.
          </div>
        )}

        {iocResult && (
          <div className="iocbox">
            {iocResult.found ? (
              <>
                <h3 className="found">
                  <CheckCircle2 size={17} />
                  Indicator found in synthetic dataset
                </h3>

                <p>
                  <b>Normalized:</b>{" "}
                  <span className="mono">
                    {iocResult.normalized_indicator ||
                      iocResult.normalized_value ||
                      ioc}
                  </span>
                </p>

                <p>
                  <b>Type:</b>{" "}
                  {iocResult.indicator_type || "—"}
                  {"  "}
                  <b>Observations:</b>{" "}
                  {iocResult.observation_count ?? 0}
                </p>

                <p>
                  <b>Highest severity:</b>{" "}
                  {iocResult.highest_severity || "—"}
                  {"  "}
                  <b>Max risk:</b>{" "}
                  {iocResult.max_risk_score ?? "—"}
                  {"  "}
                  <b>Max confidence:</b>{" "}
                  {iocResult.max_confidence_score ?? "—"}
                </p>

                <p>
                  <b>Categories:</b>{" "}
                  {(iocResult.categories || []).map((category) => (
                    <span className="tag" key={category}>
                      {category}
                    </span>
                  ))}
                </p>

                <p style={{ color: "#facc15" }}>
                  Dataset observation does not confirm compromise
                  or malicious activity.
                </p>
              </>
            ) : (
              <>
                <h3 className="notfound">
                  <XCircle size={17} />
                  Indicator not found
                </h3>

                <p>
                  {iocResult.error ||
                    "No matching observation exists in the synthetic dataset."}
                </p>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   AWARENESS CENTER
========================================================= */

function AwarenessCenter({
  selectedModule,
  setSelectedModule,
  setTab,
}) {
  return (
    <div>
      <h1>Cybersecurity Awareness Center</h1>

      <p className="subtitle">
        Learn practical defensive habits for accounts, devices,
        browsing, cloud services, and incident reporting.
      </p>

      <div
        className="summaryBox"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 20,
          flexWrap: "wrap",
        }}
      >
        <div>
          <div className="summaryIcon">
            <GraduationCap size={22} />
          </div>

          <h2>Build Better Security Habits</h2>

          <p style={{ color: "#9fb0c3" }}>
            Complete the lessons and then test your knowledge
            with the 30-question Security Awareness Quiz.
          </p>
        </div>

        <button
          className="primary"
          onClick={() => setTab("quiz")}
        >
          <Brain size={16} />
          Take Quiz
        </button>
      </div>

      <div className="moduleGrid">
        {awarenessModules.map((module) => (
          <div
            className="panel module"
            key={module.id}
            onClick={() => setSelectedModule(module)}
          >
            <div className="moduleIcon">{module.icon}</div>

            <h3>{module.title}</h3>

            <p>{module.summary}</p>

            <div className="lessonBadge">
              Open lesson <ChevronRight size={13} />
            </div>
          </div>
        ))}
      </div>

      {selectedModule && (
        <div className="panel moduleDetail">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 15,
            }}
          >
            <div>
              <div className="moduleIcon">
                {selectedModule.icon}
              </div>

              <h2>{selectedModule.title}</h2>

              <p className="subtitle">
                {selectedModule.summary}
              </p>
            </div>

            <button
              className="secondary"
              onClick={() => setSelectedModule(null)}
            >
              Close
            </button>
          </div>

          <h3>Key defensive practices</h3>

          <ul className="points">
            {selectedModule.points.map((point) => (
              <li key={point}>{point}</li>
            ))}
          </ul>

          <div
            style={{
              marginTop: 20,
              padding: 14,
              background: "#101f31",
              borderRadius: 8,
              color: "#8fa3ba",
              fontSize: 12,
            }}
          >
            Educational guidance only. Follow your organization's
            security policies and authorized reporting procedures.
          </div>
        </div>
      )}
    </div>
  );
}

/* =========================================================
   SECURITY QUIZ
========================================================= */

function SecurityQuiz({
  started,
  startQuiz,
  quizIndex,
  quizResult,
  answerQuestion,
  resetQuiz,
}) {
  if (!started) {
    return (
      <div>
        <h1>Security Awareness Quiz</h1>

        <p className="subtitle">
          30 questions covering phishing, passwords, MFA, cloud,
          mobile security, vulnerabilities, threat intelligence,
          and incident reporting.
        </p>

        <div
          className="panel"
          style={{
            textAlign: "center",
            padding: "45px 20px",
          }}
        >
          <Brain size={48} color="#60a5fa" />

          <h2>Test Your Cybersecurity Awareness</h2>

          <p style={{ color: "#8fa3ba" }}>
            Each question has one best defensive answer.
            Your score is calculated locally.
          </p>

          <button className="primary" onClick={startQuiz}>
            <Brain size={16} />
            Start 30-Question Quiz
          </button>
        </div>
      </div>
    );
  }

  if (quizResult) {
    return (
      <div>
        <h1>Quiz Result</h1>

        <p className="subtitle">
          Your result was calculated from all 30 answers.
        </p>

        <div className="panel result">
          <div className="score">{quizResult.score}%</div>

          <h2>{quizResult.label}</h2>

          <p>
            {quizResult.correct} of {quizQuestions.length} answers
            correct.
          </p>

          <div className="rec">
            <b>Learning Recommendation</b>

            <p style={{ color: "#aebdcd" }}>
              {quizResult.score >= 81
                ? "Review advanced topics and continue practicing safe verification habits."
                : quizResult.score >= 61
                ? "Review phishing, account security, and incident reporting to strengthen consistency."
                : quizResult.score >= 41
                ? "Complete the awareness lessons and retake the quiz to reinforce the fundamentals."
                : "Start with phishing, passwords and MFA, safe browsing, and incident reporting lessons before retaking the quiz."}
            </p>
          </div>

          <button className="secondary" onClick={resetQuiz}>
            <RotateCcw size={15} />
            Retake Quiz
          </button>
        </div>
      </div>
    );
  }

  const question = quizQuestions[quizIndex];

  return (
    <div>
      <h1>Security Awareness Quiz</h1>

      <p className="subtitle">
        Defensive cybersecurity learning assessment.
      </p>

      <div className="panel">
        <div className="quizTop">
          <span>
            Question {quizIndex + 1} of {quizQuestions.length}
          </span>

          <span>
            {Math.round(
              (quizIndex / quizQuestions.length) * 100
            )}
            % complete
          </span>
        </div>

        <div className="bar">
          <div
            className="fill"
            style={{
              width:
                ((quizIndex + 1) /
                  quizQuestions.length) *
                  100 +
                "%",
            }}
          />
        </div>

        <div className="question">{question.q}</div>

        {question.options.map((option, index) => (
          <button
            className="option"
            key={option}
            onClick={() => answerQuestion(index)}
          >
            {String.fromCharCode(65 + index)}. {option}
          </button>
        ))}
      </div>
    </div>
  );
}

/* =========================================================
   EXECUTIVE SUMMARY
========================================================= */

function ExecutiveSummary({
  stats,
  severityData,
  categoryData,
  vulns,
  alerts,
}) {
  const total =
    stats?.total_threats ??
    stats?.total_records ??
    "—";

  const critical =
    stats?.critical_count ??
    severityData.find((x) => x[0] === "CRITICAL")?.[1] ??
    "—";

  const high =
    stats?.high_count ??
    severityData.find((x) => x[0] === "HIGH")?.[1] ??
    "—";

  const topCategory = categoryData[0]?.[0] || "No data";

  return (
    <div>
      <h1>Executive Cybersecurity Summary</h1>

      <p className="subtitle">
        High-level defensive security observations for non-technical
        decision making.
      </p>

      <div className="grid3">
        <MetricCard title="Threat Records" value={total} />
        <MetricCard title="Critical Observations" value={critical} />
        <MetricCard title="High Observations" value={high} />
      </div>

      <div className="summaryBox" style={{ marginTop: 20 }}>
        <div className="summaryIcon">
          <BarChart3 size={22} />
        </div>

        <h2>Threat Landscape</h2>

        <p style={{ color: "#aebdcd", lineHeight: 1.7 }}>
          The demonstration dataset contains synthetic threat
          intelligence observations across multiple cybersecurity
          categories. The most frequently represented category in
          the current dashboard data is{" "}
          <b>{topCategory}</b>.
        </p>
      </div>

      <div className="grid2">
        <div className="panel">
          <h3>
            <FileWarning size={16} /> Vulnerability Exposure
          </h3>

          <p style={{ color: "#9fb0c3" }}>
            {Array.isArray(vulns)
              ? vulns.length
              : "Multiple"}{" "}
            vulnerability observations are available for awareness
            and prioritization analysis.
          </p>

          <p style={{ color: "#71869d", fontSize: 12 }}>
            Synthetic CVE-style records do not establish that a
            real environment is vulnerable.
          </p>
        </div>

        <div className="panel">
          <h3>
            <AlertTriangle size={16} /> Alert Monitoring
          </h3>

          <p style={{ color: "#9fb0c3" }}>
            {alerts?.length ?? 0} recent alerts are displayed by
            the dashboard.
          </p>

          <p style={{ color: "#71869d", fontSize: 12 }}>
            Alerts require authorized analyst review and additional
            evidence before conclusions are made.
          </p>
        </div>
      </div>

      <h2 className="sectionTitle">Defensive Priorities</h2>

      <div className="grid3">
        <Priority
          icon={<LockKeyhole size={20} />}
          title="Identity Security"
          text="Use strong unique credentials and MFA for important accounts."
        />

        <Priority
          icon={<Globe size={20} />}
          title="Phishing Resistance"
          text="Verify unexpected requests, links, attachments, and impersonation attempts."
        />

        <Priority
          icon={<Bug size={20} />}
          title="Vulnerability Management"
          text="Prioritize relevant security updates and verify exposure in authorized environments."
        />
      </div>
    </div>
  );
}

function Priority({ icon, title, text }) {
  return (
    <div className="panel">
      <div className="summaryIcon">{icon}</div>

      <h3>{title}</h3>

      <p style={{ color: "#9fb0c3", lineHeight: 1.6 }}>
        {text}
      </p>
    </div>
  );
}

/* =========================================================
   SOC WORKFLOW
========================================================= */

function SOCWorkflow() {
  const steps = [
    ["Threat Feed", Activity],
    ["IOC Detected", Search],
    ["Validation", CheckCircle2],
    ["Enrichment", Globe],
    ["Risk + Confidence", BarChart3],
    ["Alert", AlertTriangle],
    ["SOC Queue", ClipboardCheck],
    ["Analyst Triage", Target],
    ["Correlation", Network],
    ["Investigation", Search],
    ["Monitor / Resolve", ShieldCheck],
  ];

  return (
    <div>
      <h1>SOC Investigation Workflow</h1>

      <p className="subtitle">
        Defensive security operations flow used by the dashboard.
      </p>

      <div className="panel">
        <div className="workflow">
          {steps.map(([label, Icon], index) => (
            <div
              key={label}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}
            >
              <div className="workflowStep">
                <Icon size={20} color="#60a5fa" />
                <b>{label}</b>
              </div>

              {index < steps.length - 1 && (
                <ChevronRight
                  className="workflowArrow"
                  size={18}
                />
              )}
            </div>
          ))}
        </div>
      </div>

      <h2 className="sectionTitle">Important SOC Concepts</h2>

      <div className="grid3">
        <div className="panel">
          <h3>Observation</h3>

          <p style={{ color: "#9fb0c3" }}>
            A recorded piece of information from the available
            dataset or authorized telemetry.
          </p>
        </div>

        <div className="panel">
          <h3>Indicator</h3>

          <p style={{ color: "#9fb0c3" }}>
            A value such as an IP, domain, hash, URL, email domain,
            or CVE identifier that can be analyzed.
          </p>
        </div>

        <div className="panel">
          <h3>Alert</h3>

          <p style={{ color: "#9fb0c3" }}>
            A security notification created when defined evidence
            and thresholds warrant analyst attention.
          </p>
        </div>

        <div className="panel">
          <h3>Threat</h3>

          <p style={{ color: "#9fb0c3" }}>
            A security concern represented through available
            evidence and context.
          </p>
        </div>

        <div className="panel">
          <h3>Risk</h3>

          <p style={{ color: "#9fb0c3" }}>
            A calculated level of concern based on selected
            severity, evidence, recency, frequency, and context.
          </p>
        </div>

        <div className="panel">
          <h3>Confidence</h3>

          <p style={{ color: "#9fb0c3" }}>
            An estimate of the strength and quality of evidence
            supporting an assessment.
          </p>
        </div>
      </div>

      <div
        className="summaryBox"
        style={{ marginTop: 20 }}
      >
        <h3>Analyst Principle</h3>

        <p style={{ color: "#aebdcd", lineHeight: 1.7 }}>
          An IOC match, alert, correlation, or risk score should
          not automatically be treated as proof of compromise.
          Analysts should validate evidence using authorized
          internal telemetry and documented procedures.
        </p>
      </div>
    </div>
  );
}