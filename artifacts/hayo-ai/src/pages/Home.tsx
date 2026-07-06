/*
 * HAYO AI AGENT - Landing Page
 * Design: Midnight Architect - Dark Luxury Minimalism
 * Nav: Two dropdown menus (Platform + Account)
 * Grid: Organized by category (4 sections)
 */

import { useState, useEffect, useRef } from "react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/_core/hooks/useAuth";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import {
  Brain, Zap, Shield, MessageSquare, GitBranch, Layers, ArrowRight, Bot, Cpu, Globe,
  Terminal, ChevronDown, Upload, FileText, BarChart3, Code2, LayoutDashboard, CreditCard,
  User, Plug, FolderOpen, Eye, FileType, ShieldCheck, Menu, X, Swords, Briefcase, Smartphone,
  TrendingUp, ScanSearch, GraduationCap, Network, FlaskConical, Search, Send, BookOpen, Wrench,
  Settings, Lock, Database, ChevronUp,
} from "lucide-react";

const HAYO_LOGO = `${import.meta.env.BASE_URL ?? "/"}logo.png`;
const HERO_BG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663136108263/gamB6PqNYpBtJh7rZp3Wsb/hero-bg-YVVRgkSHKjvsVpBnH2UZWY.webp";
const AI_BRAIN = "https://d2xsxph8kpxj0f.cloudfront.net/310519663136108263/gamB6PqNYpBtJh7rZp3Wsb/ai-brain-NJC34aooSKWh2r9bfbx2rL.webp";
const AGENTS_IMG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663136108263/gamB6PqNYpBtJh7rZp3Wsb/agents-illustration-TFass5NhHkfaPTw5ttAzSp.webp";
const DASHBOARD_IMG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663136108263/gamB6PqNYpBtJh7rZp3Wsb/dashboard-preview-TFbGCfSybWYKVMeWkuDYEm.webp";

const fadeUp = {
  hidden: { opacity: 0, y: 30 },
  visible: (i: number) => ({ opacity: 1, y: 0, transition: { delay: i * 0.1, duration: 0.6 } }),
};

// Grid columns scale down to the actual item count so short sections (e.g. 2 items)
// don't leave a half-empty row on wide screens.
const GRID_COLS_BY_COUNT: Record<2 | 3 | 4 | 5, string> = {
  2: "sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-2",
  3: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3",
  4: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4",
  5: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5",
};

function TypeWriter({ text, speed = 50 }: { text: string; speed?: number }) {
  const [displayed, setDisplayed] = useState("");
  const [index, setIndex] = useState(0);
  useEffect(() => { setDisplayed(""); setIndex(0); }, [text]);
  useEffect(() => {
    if (index < text.length) {
      const timer = setTimeout(() => { setDisplayed((prev) => prev + text[index]); setIndex((prev) => prev + 1); }, speed);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [index, text, speed]);
  return <span>{displayed}{index < text.length && <span className="typing-cursor" />}</span>;
}

// ─── Dropdown Menu Component ──────────────────────────────────────────
function NavDropdown({
  label,
  icon: Icon,
  groups,
}: {
  label: string;
  icon: React.ElementType;
  groups: {
    title: string;
    items: { href: string; icon: React.ElementType; label: string; desc?: string }[];
  }[];
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-all"
      >
        <Icon className="w-4 h-4" />
        {label}
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="absolute top-full mt-2 left-0 z-50 bg-background/95 backdrop-blur-xl border border-border/50 rounded-xl shadow-2xl shadow-black/40 p-3 min-w-[520px]"
          style={{ direction: "rtl" }}
        >
          <div className="grid grid-cols-2 gap-4">
            {groups.map((group) => (
              <div key={group.title}>
                <p className="text-xs font-semibold text-muted-foreground px-2 py-1 mb-1 uppercase tracking-wider">
                  {group.title}
                </p>
                <div className="space-y-0.5">
                  {group.items.map((item) => (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={() => setOpen(false)}
                      className="flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-all group"
                    >
                      <item.icon className="w-4 h-4 text-indigo-400 group-hover:text-indigo-300 flex-shrink-0" />
                      <div>
                        <div className="font-medium text-foreground/80 group-hover:text-foreground">{item.label}</div>
                        {item.desc && <div className="text-xs text-muted-foreground/70">{item.desc}</div>}
                      </div>
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
}

// ─── Category Section Component ───────────────────────────────────────
function CategorySection({
  title,
  subtitle,
  color,
  items,
  delay = 0,
}: {
  title: string;
  subtitle: string;
  color: string;
  delay?: number;
  items: {
    icon: React.ElementType;
    title: string;
    desc: string;
    href: string;
    iconBg: string;
  }[];
}) {
  return (
    <motion.div
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-50px" }}
      custom={delay}
      variants={fadeUp}
    >
      <div className="flex items-center gap-3 mb-4">
        <div className={`h-0.5 w-8 rounded-full bg-gradient-to-r ${color}`} />
        <div>
          <h3 className="font-heading font-bold text-lg text-foreground">{title}</h3>
          <p className="text-xs text-muted-foreground">{subtitle}</p>
        </div>
      </div>
      <div className={`grid gap-3 ${GRID_COLS_BY_COUNT[Math.min(items.length, 5) as 2 | 3 | 4 | 5] ?? GRID_COLS_BY_COUNT[5]}`}>
        {items.map((item, i) => (
          <motion.div
            key={item.href + item.title}
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.05 }}
          >
            <Link href={item.href}>
              <div className="group glass-card rounded-xl p-4 hover:border-indigo-500/30 transition-all duration-300 hover:glow-indigo cursor-pointer h-full">
                <div className={`w-10 h-10 rounded-lg ${item.iconBg} flex items-center justify-center mb-3 group-hover:scale-110 transition-transform`}>
                  <item.icon className="w-5 h-5 text-foreground" />
                </div>
                <h4 className="font-heading font-semibold text-xs mb-1 text-foreground">{item.title}</h4>
                <p className="text-muted-foreground text-xs leading-relaxed line-clamp-2">{item.desc}</p>
              </div>
            </Link>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}

export default function Home() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { t } = useTranslation();
  // Owner-only control panels (subscription/codes management, model config,
  // executive agent, maintenance) must never surface to guests or investors —
  // they only appear once the owner/admin is signed in.
  const { user } = useAuth();
  const isAdmin = (user as { role?: string } | null)?.role === "admin";
  // "/" is the public welcome/intro landing page and it should always render here
  // (for both guests and logged-in users) — the owner wants the intro to show when
  // opening the platform link, not flash-and-redirect. Auth resilience + the
  // owner→admin backstop in the API handle the "plan looks reverted" concern
  // separately, so no client redirect is needed. Authenticated users reach their
  // dashboard via the nav/login buttons.

  // ─── Platform Dropdown Groups ──────────────────────────────────────
  const platformGroups = [
    {
      title: t("home.grpAI"),
      items: [
        { href: "/chat",            icon: MessageSquare, label: t("home.t_chat"),          desc: t("home.d_chat") },
        { href: "/agent",           icon: Terminal,      label: t("home.t_agent"),         desc: t("home.d_agent") },
        { href: "/war-room",        icon: Swords,        label: t("home.t_warRoom"),       desc: t("home.d_warRoom") },
        { href: "/prompt-factory",  icon: FlaskConical,  label: t("home.t_promptFactory"), desc: t("home.d_promptFactory") },
        { href: "/mindmap",         icon: Network,       label: t("home.t_mindmap"),       desc: t("home.d_mindmap") },
      ],
    },
    {
      title: t("home.grpDev"),
      items: [
        { href: "/byoc",           icon: Code2,      label: t("home.t_byoc"),         desc: t("home.d_byoc") },
        { href: "/app-builder",    icon: Smartphone, label: t("home.t_appBuilder"),   desc: t("home.d_appBuilder") },
        { href: "/reverse",        icon: ScanSearch, label: t("home.t_reverse"),      desc: t("home.d_reverse") },
        { href: "/integrations",   icon: Plug,       label: t("home.t_integrations"), desc: t("home.d_integrations") },
        { href: "/osint",          icon: Search,     label: t("home.t_osint"),        desc: t("home.d_osint") },
      ],
    },
    {
      title: t("home.grpBiz"),
      items: [
        { href: "/office",  icon: Briefcase,    label: t("home.t_office"),    desc: t("home.d_office") },
        { href: "/studies", icon: GraduationCap,label: t("home.t_studies"),   desc: t("home.d_studies") },
        { href: "/islam",   icon: BookOpen,     label: t("home.t_islam"),     desc: t("home.d_islam") },
        { href: "/converter",icon: FileType,   label: t("home.t_converter"), desc: t("home.d_converter") },
      ],
    },
    {
      title: t("home.grpTrade"),
      items: [
        { href: "/trading",         icon: TrendingUp, label: t("home.t_trading"),        desc: t("home.d_trading") },
        { href: "/trading-brokers", icon: BarChart3,  label: t("home.t_tradingBrokers"), desc: t("home.d_tradingBrokers") },
        { href: "/ea-factory",      icon: Cpu,        label: t("home.t_eaFactory"),      desc: t("home.d_eaFactory") },
        { href: "/telegram",        icon: Send,       label: t("home.t_telegram"),       desc: t("home.d_telegram") },
      ],
    },
  ];

  const accountGroups = [
    {
      title: t("home.grpAccount"),
      items: [
        { href: "/account",    icon: User,          label: t("home.t_account"),   desc: t("home.d_account") },
        { href: "/dashboard",  icon: LayoutDashboard,label: t("home.t_dashboard"),desc: t("home.d_dashboard") },
        { href: "/pricing",    icon: CreditCard,    label: t("home.t_pricing"),   desc: t("home.d_pricing") },
        { href: "/payment",    icon: CreditCard,    label: t("home.t_payment"),   desc: t("home.d_payment") },
      ],
    },
    // Admin control panels stay hidden from guests/investors — only the owner sees them.
    ...(isAdmin
      ? [{
          title: t("home.grpAdmin"),
          items: [
            { href: "/model-settings", icon: Settings,      label: t("home.t_modelSettings"), desc: t("home.d_modelSettings") },
            { href: "/ai-agent",      icon: Bot,           label: t("home.t_aiAgent"),       desc: t("home.d_aiAgent") },
            { href: "/admin",          icon: ShieldCheck,   label: t("home.t_admin"),         desc: t("home.d_admin") },
            { href: "/maintenance",    icon: Wrench,        label: t("home.t_maintenance"),   desc: t("home.d_maintenance") },
          ],
        }]
      : []),
  ];

  // ─── Quick Access Sections ─────────────────────────────────────────
  const aiSection = [
    { icon: MessageSquare, title: t("home.t_chat"),          desc: t("home.d_chat"),          href: "/chat",           iconBg: "bg-blue-500/20" },
    { icon: Terminal,      title: t("home.t_agent"),         desc: t("home.d_agent"),         href: "/agent",          iconBg: "bg-emerald-500/20" },
    { icon: Swords,        title: t("home.t_warRoom"),       desc: t("home.d_warRoom"),       href: "/war-room",       iconBg: "bg-red-500/20" },
    { icon: FlaskConical,  title: t("home.t_promptFactory"), desc: t("home.d_promptFactory"), href: "/prompt-factory", iconBg: "bg-fuchsia-500/20" },
    { icon: Network,       title: t("home.t_mindmap"),       desc: t("home.d_mindmap"),       href: "/mindmap",        iconBg: "bg-cyan-500/20" },
  ];

  const devSection = [
    { icon: Code2,      title: t("home.t_byoc"),         desc: t("home.d_byoc"),         href: "/byoc",         iconBg: "bg-orange-500/20" },
    { icon: Smartphone, title: t("home.t_appBuilder"),   desc: t("home.d_appBuilder"),   href: "/app-builder",  iconBg: "bg-pink-500/20" },
    { icon: ScanSearch, title: t("home.t_reverse"),      desc: t("home.d_reverse"),      href: "/reverse",      iconBg: "bg-amber-500/20" },
    { icon: Shield,     title: t("home.t_pentest"),      desc: t("home.d_pentest"),      href: "/pentest",      iconBg: "bg-rose-500/20" },
    { icon: Wrench,     title: t("home.t_smartFixer"),   desc: t("home.d_smartFixer"),   href: "/smart-fixer",  iconBg: "bg-teal-500/20" },
    { icon: Plug,       title: t("home.t_integrations"), desc: t("home.d_integrations"), href: "/integrations", iconBg: "bg-green-500/20" },
    { icon: Search,     title: t("home.t_osint"),        desc: t("home.d_osint"),        href: "/osint",        iconBg: "bg-slate-500/20" },
    { icon: FolderOpen, title: t("home.t_projects"),     desc: t("home.d_projects"),     href: "/projects",     iconBg: "bg-zinc-500/20" },
  ];

  const businessSection = [
    { icon: Briefcase,     title: t("home.t_office"),        desc: t("home.d_office"),        href: "/office",         iconBg: "bg-violet-500/20" },
    { icon: GraduationCap, title: t("home.t_studies"),       desc: t("home.d_studies"),       href: "/studies",        iconBg: "bg-purple-500/20" },
    { icon: BookOpen,      title: t("home.t_islam"),         desc: t("home.d_islam"),         href: "/islam",          iconBg: "bg-emerald-700/30" },
    { icon: FileType,      title: t("home.t_converter"),     desc: t("home.d_converter"),     href: "/converter",      iconBg: "bg-sky-500/20" },
  ];

  const tradingSection = [
    { icon: TrendingUp, title: t("home.t_trading"),         desc: t("home.d_trading"),         href: "/trading",         iconBg: "bg-emerald-500/20" },
    { icon: BarChart3,  title: t("home.t_tradingBrokers"),  desc: t("home.d_tradingBrokers"),  href: "/trading-brokers", iconBg: "bg-blue-500/20" },
    { icon: Cpu,        title: t("home.t_eaFactory"),       desc: t("home.d_eaFactory"),       href: "/ea-factory",      iconBg: "bg-amber-500/20" },
    { icon: Send,       title: t("home.t_telegram"),        desc: t("home.d_telegram"),        href: "/telegram",        iconBg: "bg-cyan-500/20" },
  ];

  const adminSection = [
    { icon: Settings,   title: t("home.t_modelSettings"), desc: t("home.d_modelSettings"), href: "/model-settings", iconBg: "bg-indigo-500/20" },
    { icon: Bot,        title: t("home.t_aiAgent"),       desc: t("home.d_aiAgent"),       href: "/ai-agent",       iconBg: "bg-violet-500/20" },
    { icon: ShieldCheck,title: t("home.t_admin"),         desc: t("home.d_admin"),         href: "/admin",          iconBg: "bg-amber-500/20" },
    { icon: Wrench,     title: t("home.t_maintenance"),   desc: t("home.d_maintenance"),   href: "/maintenance",    iconBg: "bg-red-500/20" },
  ];

  const agents = [
    { name: t("agents.planner"), desc: t("agents.plannerDesc"), icon: GitBranch, color: "from-indigo-500 to-blue-500" },
    { name: t("agents.worker"), desc: t("agents.workerDesc"), icon: Cpu, color: "from-emerald-500 to-teal-500" },
    { name: t("agents.critic"), desc: t("agents.criticDesc"), icon: Shield, color: "from-amber-500 to-orange-500" },
    { name: t("agents.coordinator"), desc: t("agents.coordinatorDesc"), icon: Layers, color: "from-violet-500 to-purple-500" },
  ];

  const features = [
    { icon: Brain, title: t("home.feat1Title"), desc: t("home.feat1Desc") },
    { icon: Upload, title: t("home.feat2Title"), desc: t("home.feat2Desc") },
    { icon: Terminal, title: t("home.feat3Title"), desc: t("home.feat3Desc") },
    { icon: BarChart3, title: t("home.feat4Title"), desc: t("home.feat4Desc") },
    { icon: MessageSquare, title: t("home.feat5Title"), desc: t("home.feat5Desc") },
    { icon: Bot, title: t("home.feat6Title"), desc: t("home.feat6Desc") },
  ];

  return (
    <div className="min-h-screen bg-background text-foreground overflow-x-hidden">
      {/* ─── Navigation ─────────────────────────────────────────────── */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border/40 bg-background/80 backdrop-blur-xl">
        <div className="container flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-3 group flex-shrink-0">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-9 h-9 rounded-lg shadow-lg shadow-indigo-500/20 group-hover:shadow-indigo-500/40 transition-shadow" />
            <span className="font-heading font-bold text-lg tracking-tight">HAYO AI</span>
          </Link>

          {/* Desktop: Two Dropdown Menus */}
          <div className="hidden lg:flex items-center gap-2">
            <NavDropdown label={t("home.navPlatform")} icon={Globe} groups={platformGroups} />
            <NavDropdown label={t("home.navAccount")} icon={User} groups={accountGroups} />
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <Link href="/agent" className="hidden sm:block">
              <Button variant="outline" size="sm" className="border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/10 gap-1.5">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                </span>
                {t("home.executiveAgent")}
              </Button>
            </Link>
            <button onClick={() => setMobileMenuOpen(!mobileMenuOpen)} className="lg:hidden p-2 rounded-lg hover:bg-accent transition-colors">
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="lg:hidden border-t border-border/40 bg-background/95 backdrop-blur-xl max-h-[80vh] overflow-y-auto">
            <div className="container py-4 space-y-4">
              {[...platformGroups, ...accountGroups].map((group) => (
                <div key={group.title}>
                  <p className="text-xs font-semibold text-muted-foreground px-2 mb-2">{group.title}</p>
                  <div className="grid grid-cols-2 gap-1">
                    {group.items.map((item) => (
                      <Link key={item.href} href={item.href} className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-all" onClick={() => setMobileMenuOpen(false)}>
                        <item.icon className="w-4 h-4 text-indigo-400" />
                        {item.label}
                      </Link>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </nav>

      {/* ─── Hero Section ───────────────────────────────────────────── */}
      <section className="relative min-h-screen flex items-center pt-16 overflow-hidden">
        <div className="absolute inset-0 z-0">
          <img src={HERO_BG} alt="" className="w-full h-full object-cover opacity-30" />
          <div className="absolute inset-0 bg-gradient-to-b from-background/70 via-background/85 to-background" />
          <div className="aurora" />
          <div className="absolute inset-0 bg-grid" />
        </div>

        <div className="container relative z-10 grid lg:grid-cols-2 gap-12 items-center py-20">
          <motion.div initial="hidden" animate="visible" className="space-y-8">
            <motion.div custom={0} variants={fadeUp} className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-indigo-500/30 bg-indigo-500/10 text-indigo-300 text-sm font-medium backdrop-blur-sm shadow-lg shadow-indigo-500/10">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-400" />
              </span>
              {t("home.poweredBy")}
            </motion.div>

            <motion.h1 custom={1} variants={fadeUp} className="font-heading text-5xl md:text-6xl lg:text-7xl font-extrabold leading-[1.1] tracking-tight">
              <span className="block">{t("home.heroTitle1")}</span>
              <span className="block gradient-text">{t("home.heroTitle2")}</span>
            </motion.h1>

            <motion.p custom={2} variants={fadeUp} className="text-lg md:text-xl text-muted-foreground max-w-lg leading-relaxed">
              <TypeWriter text={t("home.heroDesc")} speed={30} />
            </motion.p>

            <motion.div custom={3} variants={fadeUp} className="flex flex-wrap gap-4">
              <Link href="/chat">
                <Button size="lg" className="bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 text-white shadow-xl shadow-indigo-500/25 text-base px-8 h-12">
                  {t("home.startChat")}
                  <ArrowRight className="w-4 h-4 mr-2 rtl:rotate-180" />
                </Button>
              </Link>
              <Link href="/agent">
                <Button variant="outline" size="lg" className="border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/10 text-base px-8 h-12 gap-2">
                  <Terminal className="w-4 h-4" />
                  {t("home.executiveAgent")}
                </Button>
              </Link>
              <Link href="/byoc">
                <Button variant="outline" size="lg" className="border-orange-500/50 text-orange-400 hover:bg-orange-500/10 text-base px-8 h-12 gap-2">
                  <Code2 className="w-4 h-4" />
                  {t("home.byocDev")}
                </Button>
              </Link>
            </motion.div>

            <motion.div custom={4} variants={fadeUp} className="grid grid-cols-4 gap-3 pt-4 max-w-lg">
              {[
                { value: "6+",  label: t("home.statModels") },
                { value: "25+", label: t("home.statTools") },
                { value: "10",  label: t("home.statLangs") },
                { value: "35+", label: t("home.statIntegrations") },
              ].map((stat) => (
                <div key={stat.label} className="gradient-border rounded-xl px-2 py-3 text-center backdrop-blur-sm">
                  <div className="text-2xl font-heading font-bold gradient-text">{stat.value}</div>
                  <div className="text-[11px] text-muted-foreground mt-0.5 leading-tight">{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </motion.div>

          <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.4, duration: 0.8 }} className="hidden lg:flex justify-center">
            <div className="relative">
              <div className="absolute -inset-4 bg-gradient-to-r from-indigo-500/20 to-violet-500/20 rounded-full blur-3xl" />
              <img src={AI_BRAIN} alt="HAYO AI Brain" className="relative w-[420px] h-[420px] object-contain animate-float drop-shadow-2xl" />
            </div>
          </motion.div>
        </div>

        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 z-10">
          <a href="#quick-access"><ChevronDown className="w-6 h-6 text-muted-foreground animate-bounce" /></a>
        </div>
      </section>

      {/* ─── Quick Access — 5 Category Sections ─────────────────────── */}
      <section id="quick-access" className="py-24 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-indigo-500/[0.02] to-transparent" />
        <div className="container relative">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-100px" }} className="text-center mb-16 space-y-4">
            <motion.span custom={0} variants={fadeUp} className="text-sm font-medium text-indigo-400 tracking-widest uppercase">{t("home.quickAccess")}</motion.span>
            <motion.h2 custom={1} variants={fadeUp} className="font-heading text-4xl md:text-5xl font-bold tracking-tight">
              {t("home.allTools").split(" ").slice(0, -2).join(" ")}{" "}
              <span className="gradient-text">{t("home.allTools").split(" ").slice(-2).join(" ")}</span>
            </motion.h2>
            <motion.p custom={2} variants={fadeUp} className="text-muted-foreground text-lg max-w-2xl mx-auto">{t("home.allToolsDesc")}</motion.p>
          </motion.div>

          <div className="space-y-12">
            <CategorySection
              title={t("home.secAITitle")}
              subtitle={t("home.secAISub")}
              color="from-blue-500 to-indigo-500"
              items={aiSection}
              delay={0}
            />
            <CategorySection
              title={t("home.secDevTitle")}
              subtitle={t("home.secDevSub")}
              color="from-orange-500 to-amber-500"
              items={devSection}
              delay={1}
            />
            <CategorySection
              title={t("home.secBizTitle")}
              subtitle={t("home.secBizSub")}
              color="from-violet-500 to-purple-500"
              items={businessSection}
              delay={2}
            />
            <CategorySection
              title={t("home.secTradeTitle")}
              subtitle={t("home.secTradeSub")}
              color="from-emerald-500 to-green-500"
              items={tradingSection}
              delay={3}
            />
            {isAdmin && (
              <CategorySection
                title={t("home.secAdminTitle")}
                subtitle={t("home.secAdminSub")}
                color="from-slate-500 to-zinc-500"
                items={adminSection}
                delay={4}
              />
            )}
          </div>
        </div>
      </section>

      {/* ─── Features Section ────────────────────────────────────────── */}
      <section id="features" className="py-24 relative">
        <div className="container">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-100px" }} className="text-center mb-16 space-y-4">
            <motion.span custom={0} variants={fadeUp} className="text-sm font-medium text-indigo-400 tracking-widest uppercase">{t("home.features")}</motion.span>
            <motion.h2 custom={1} variants={fadeUp} className="font-heading text-4xl md:text-5xl font-bold tracking-tight">
              <span className="gradient-text">{t("home.unlimitedCapabilities")}</span>
            </motion.h2>
            <motion.p custom={2} variants={fadeUp} className="text-muted-foreground text-lg max-w-2xl mx-auto">{t("home.featuresDesc")}</motion.p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, i) => (
              <motion.div key={feature.title} initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-50px" }} custom={i} variants={fadeUp}
                className="group glass-card rounded-xl p-6 hover:border-indigo-500/30 transition-all duration-300 hover:glow-indigo">
                <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-indigo-500/20 to-violet-500/20 flex items-center justify-center mb-4 group-hover:from-indigo-500/30 group-hover:to-violet-500/30 transition-colors">
                  <feature.icon className="w-6 h-6 text-indigo-400" />
                </div>
                <h3 className="font-heading font-semibold text-lg mb-2 text-foreground">{feature.title}</h3>
                <p className="text-muted-foreground text-sm leading-relaxed">{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── Agents Section ──────────────────────────────────────────── */}
      <section id="agents" className="py-24 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-indigo-500/[0.03] to-transparent" />
        <div className="container relative">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-100px" }} className="text-center mb-16 space-y-4">
            <motion.span custom={0} variants={fadeUp} className="text-sm font-medium text-indigo-400 tracking-widest uppercase">{t("home.agentSystem")}</motion.span>
            <motion.h2 custom={1} variants={fadeUp} className="font-heading text-4xl md:text-5xl font-bold tracking-tight">
              <span className="gradient-text">{t("home.fourAgents")}</span>
            </motion.h2>
          </motion.div>

          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <motion.div initial={{ opacity: 0, x: -40 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ duration: 0.7 }}>
              <img src={AGENTS_IMG} alt="HAYO AI Agents" className="w-full rounded-2xl shadow-2xl shadow-black/30 border border-border/40" />
            </motion.div>

            <div className="space-y-4">
              {agents.map((agent, i) => (
                <motion.div key={agent.name} initial="hidden" whileInView="visible" viewport={{ once: true }} custom={i} variants={fadeUp}
                  className="glass-card rounded-xl p-5 flex items-start gap-4 hover:border-indigo-500/30 transition-all duration-300">
                  <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${agent.color} flex items-center justify-center flex-shrink-0 shadow-lg`}>
                    <agent.icon className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="font-heading font-semibold text-foreground">{agent.name}</h3>
                    <p className="text-sm text-muted-foreground mt-1">{agent.desc}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ─── Demo / Dashboard Preview ────────────────────────────────── */}
      <section id="demo" className="py-24 relative">
        <div className="container">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-100px" }} className="text-center mb-16 space-y-4">
            <motion.span custom={0} variants={fadeUp} className="text-sm font-medium text-indigo-400 tracking-widest uppercase">{t("home.demo")}</motion.span>
            <motion.h2 custom={1} variants={fadeUp} className="font-heading text-4xl md:text-5xl font-bold tracking-tight">
              <span className="gradient-text">{t("home.proDashboard")}</span>
            </motion.h2>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 40 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.8 }} className="relative">
            <div className="absolute -inset-4 bg-gradient-to-r from-indigo-500/10 to-violet-500/10 rounded-3xl blur-2xl" />
            <div className="relative rounded-2xl overflow-hidden border border-border/40 shadow-2xl shadow-black/40">
              <img src={DASHBOARD_IMG} alt="HAYO AI Dashboard" className="w-full" />
            </div>
          </motion.div>
        </div>
      </section>

      {/* ─── CTA Section ─────────────────────────────────────────────── */}
      <section className="py-24 relative">
        <div className="absolute inset-0 bg-gradient-to-t from-indigo-500/[0.05] to-transparent" />
        <div className="container relative">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} className="glass-card rounded-2xl p-12 md:p-16 text-center space-y-6 glow-indigo">
            <motion.h2 custom={0} variants={fadeUp} className="font-heading text-3xl md:text-4xl font-bold">
              {t("home.ctaTitle") || "ابدأ رحلتك مع HAYO AI الآن"}
            </motion.h2>
            <motion.p custom={1} variants={fadeUp} className="text-muted-foreground text-lg max-w-xl mx-auto">
              {t("home.ctaDesc") || "منصة AI عربية شاملة — أكثر من 22 أداة، 6 نماذج، 35+ تكامل"}
            </motion.p>
            <motion.div custom={2} variants={fadeUp} className="flex flex-wrap gap-4 justify-center">
              <Link href="/chat">
                <Button size="lg" className="bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 text-white shadow-xl shadow-indigo-500/25 text-base px-10 h-12">
                  {t("home.startChat")}
                  <ArrowRight className="w-4 h-4 mr-2 rtl:rotate-180" />
                </Button>
              </Link>
              <Link href="/pricing">
                <Button variant="outline" size="lg" className="border-border/60 text-base px-10 h-12">
                  <CreditCard className="w-4 h-4 ml-2" />
                  {t("home.viewPricing")}
                </Button>
              </Link>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* ─── Footer ──────────────────────────────────────────────────── */}
      <footer className="border-t border-border/40 py-8">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <img src={HAYO_LOGO} alt="HAYO AI" className="w-7 h-7 rounded-md" />
            <span className="text-sm font-heading font-semibold">HAYO AI</span>
          </div>
          <p className="text-xs text-muted-foreground text-center">
            {t("home.copyright") || "© 2025 HAYO AI — منصة ذكاء اصطناعي عربية شاملة"}
          </p>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <Link href="/pricing" className="hover:text-foreground transition-colors">{t("nav.pricing")}</Link>
            {isAdmin && <Link href="/admin" className="hover:text-foreground transition-colors">{t("nav.admin")}</Link>}
            <Link href="/dashboard" className="hover:text-foreground transition-colors">{t("nav.dashboard")}</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
