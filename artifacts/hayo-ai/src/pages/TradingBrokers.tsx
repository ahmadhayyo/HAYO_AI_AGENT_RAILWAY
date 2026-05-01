/**
 * Trading Brokers — ربط وإدارة حسابات منصات التداول الثنائي
 * Route: /trading-brokers
 * Features: إضافة حسابات Quotex/IQ Option/Pocket Option, سجل الصفقات, إحصائيات الأداء
 */

import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import {
  Home, Plus, Trash2, TrendingUp, TrendingDown, DollarSign,
  BarChart3, Loader2, RefreshCw, Wallet, Activity, Target,
  CheckCircle2, XCircle, Clock, ArrowUpRight, ArrowDownRight,
  AlertTriangle, ChevronDown, ChevronUp, X,
} from "lucide-react";
import LanguageSwitcher from "@/components/LanguageSwitcher";

// ─── Platform Config ─────────────────────────────────────────────
const PLATFORMS = {
  quotex: {
    name: "Quotex",
    color: "from-blue-500 to-blue-700",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    text: "text-blue-400",
    logo: "Q",
    url: "https://quotex.com",
  },
  iqoption: {
    name: "IQ Option",
    color: "from-green-500 to-emerald-700",
    bg: "bg-green-500/10",
    border: "border-green-500/30",
    text: "text-green-400",
    logo: "IQ",
    url: "https://iqoption.com",
  },
  pocketoption: {
    name: "Pocket Option",
    color: "from-purple-500 to-violet-700",
    bg: "bg-purple-500/10",
    border: "border-purple-500/30",
    text: "text-purple-400",
    logo: "PO",
    url: "https://pocketoption.com",
  },
  olymptrade: {
    name: "Olymp Trade",
    color: "from-orange-500 to-amber-700",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    text: "text-orange-400",
    logo: "OT",
    url: "https://olymptrade.com",
  },
} as const;

type Platform = keyof typeof PLATFORMS;

const RESULT_CONFIG = {
  win: { icon: CheckCircle2, text: "ربح", color: "text-emerald-400", bg: "bg-emerald-500/10" },
  loss: { icon: XCircle, text: "خسارة", color: "text-red-400", bg: "bg-red-500/10" },
  pending: { icon: Clock, text: "قيد التنفيذ", color: "text-yellow-400", bg: "bg-yellow-500/10" },
  draw: { icon: Activity, text: "تعادل", color: "text-gray-400", bg: "bg-gray-500/10" },
  cancelled: { icon: X, text: "ملغاة", color: "text-gray-500", bg: "bg-gray-500/10" },
};

// ─── Add Account Modal ─────────────────────────────────────────────
function AddAccountModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [platform, setPlatform] = useState<Platform>("quotex");
  const [accountName, setAccountName] = useState("");
  const [accountEmail, setAccountEmail] = useState("");
  const [balance, setBalance] = useState("");
  const [currency, setCurrency] = useState("USD");

  const addMutation = trpc.hayo.broker.addAccount.useMutation({
    onSuccess: () => {
      toast.success("تم ربط الحساب بنجاح ✅");
      onSuccess();
      onClose();
    },
    onError: (err) => toast.error(err.message),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    addMutation.mutate({
      platform,
      accountName: accountName.trim() || undefined,
      accountEmail: accountEmail.trim() || undefined,
      balance: balance ? parseFloat(balance) : undefined,
      currency,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0f1117] border border-white/10 rounded-2xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-6 border-b border-white/10">
          <h2 className="text-lg font-bold text-white">ربط حساب تداول جديد</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
            <X className="size-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Platform Select */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">اختر المنصة</label>
            <div className="grid grid-cols-2 gap-2">
              {(Object.keys(PLATFORMS) as Platform[]).map((p) => {
                const cfg = PLATFORMS[p];
                return (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setPlatform(p)}
                    className={`flex items-center gap-2 p-3 rounded-xl border transition-all ${
                      platform === p
                        ? `${cfg.bg} ${cfg.border} ${cfg.text}`
                        : "border-white/10 text-gray-400 hover:border-white/20"
                    }`}
                  >
                    <span className={`w-8 h-8 rounded-lg bg-gradient-to-br ${cfg.color} flex items-center justify-center text-white text-xs font-bold`}>
                      {cfg.logo}
                    </span>
                    <span className="font-medium text-sm">{cfg.name}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Account Name */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">اسم الحساب (اختياري)</label>
            <input
              type="text"
              value={accountName}
              onChange={(e) => setAccountName(e.target.value)}
              placeholder="مثال: حساب رئيسي"
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 text-sm"
            />
          </div>

          {/* Email */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">البريد الإلكتروني (اختياري)</label>
            <input
              type="email"
              value={accountEmail}
              onChange={(e) => setAccountEmail(e.target.value)}
              placeholder="email@example.com"
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 text-sm"
              dir="ltr"
            />
          </div>

          {/* Balance */}
          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-2">
              <label className="block text-sm text-gray-400 mb-1">الرصيد الحالي</label>
              <input
                type="number"
                value={balance}
                onChange={(e) => setBalance(e.target.value)}
                placeholder="0.00"
                min="0"
                step="0.01"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 text-sm"
                dir="ltr"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">العملة</label>
              <select
                value={currency}
                onChange={(e) => setCurrency(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2.5 text-white focus:outline-none focus:border-blue-500/50 text-sm"
              >
                {["USD", "EUR", "GBP", "AED", "SAR", "EGP"].map((c) => (
                  <option key={c} value={c} className="bg-[#0f1117]">{c}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex gap-3 pt-2">
            <Button type="button" variant="ghost" onClick={onClose} className="flex-1 text-gray-400">
              إلغاء
            </Button>
            <Button
              type="submit"
              disabled={addMutation.isPending}
              className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white"
            >
              {addMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />}
              ربط الحساب
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Add Trade Modal ─────────────────────────────────────────────
function AddTradeModal({ accountId, onClose, onSuccess }: { accountId: number; onClose: () => void; onSuccess: () => void }) {
  const [asset, setAsset] = useState("EUR/USD");
  const [direction, setDirection] = useState<"call" | "put">("call");
  const [amount, setAmount] = useState("");
  const [duration, setDuration] = useState("60");
  const [result, setResult] = useState<"pending" | "win" | "loss">("pending");
  const [profitLoss, setProfitLoss] = useState("");
  const [signalSource, setSignalSource] = useState("يدوي");

  const addTrade = trpc.hayo.broker.addTrade.useMutation({
    onSuccess: () => { toast.success("تم إضافة الصفقة ✅"); onSuccess(); onClose(); },
    onError: (err) => toast.error(err.message),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!amount) return toast.error("أدخل مبلغ الصفقة");
    addTrade.mutate({
      accountId,
      asset,
      direction,
      amount: parseFloat(amount),
      durationSeconds: parseInt(duration),
      result,
      profitLoss: profitLoss ? parseFloat(profitLoss) : undefined,
      signalSource,
    });
  };

  const ASSETS = ["EUR/USD", "GBP/USD", "USD/JPY", "AUD/USD", "USD/CHF", "XAU/USD", "BTC/USD", "ETH/USD", "OTC EUR/USD", "OTC GBP/USD"];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0f1117] border border-white/10 rounded-2xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-6 border-b border-white/10">
          <h2 className="text-lg font-bold text-white">تسجيل صفقة جديدة</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors"><X className="size-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">الأصل</label>
            <select
              value={asset}
              onChange={(e) => setAsset(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-blue-500/50 text-sm"
            >
              {ASSETS.map((a) => <option key={a} value={a} className="bg-[#0f1117]">{a}</option>)}
            </select>
          </div>

          {/* Direction */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">الاتجاه</label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setDirection("call")}
                className={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all ${direction === "call" ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-400" : "border-white/10 text-gray-400"}`}
              >
                <ArrowUpRight className="size-4" /> CALL (شراء)
              </button>
              <button
                type="button"
                onClick={() => setDirection("put")}
                className={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all ${direction === "put" ? "bg-red-500/20 border-red-500/40 text-red-400" : "border-white/10 text-gray-400"}`}
              >
                <ArrowDownRight className="size-4" /> PUT (بيع)
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm text-gray-400 mb-1">المبلغ ($)</label>
              <input type="number" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="10.00" min="1" step="0.01" className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 text-sm" dir="ltr" />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">المدة (ثانية)</label>
              <select value={duration} onChange={(e) => setDuration(e.target.value)} className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-blue-500/50 text-sm">
                {[30, 60, 120, 180, 300, 600].map((d) => <option key={d} value={d} className="bg-[#0f1117]">{d < 60 ? `${d}ث` : `${d / 60}د`}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">نتيجة الصفقة</label>
            <div className="grid grid-cols-3 gap-2">
              {(["win", "loss", "pending"] as const).map((r) => {
                const cfg = RESULT_CONFIG[r];
                const Icon = cfg.icon;
                return (
                  <button key={r} type="button" onClick={() => setResult(r)} className={`flex items-center justify-center gap-1.5 p-2.5 rounded-xl border text-sm transition-all ${result === r ? `${cfg.bg} ${cfg.color} border-current/30` : "border-white/10 text-gray-400"}`}>
                    <Icon className="size-3.5" /> {cfg.text}
                  </button>
                );
              })}
            </div>
          </div>

          {result !== "pending" && (
            <div>
              <label className="block text-sm text-gray-400 mb-1">الربح/الخسارة ($)</label>
              <input type="number" value={profitLoss} onChange={(e) => setProfitLoss(e.target.value)} placeholder={result === "win" ? "+8.50" : "-10.00"} step="0.01" className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 text-sm" dir="ltr" />
            </div>
          )}

          <div>
            <label className="block text-sm text-gray-400 mb-1">مصدر الإشارة</label>
            <input type="text" value={signalSource} onChange={(e) => setSignalSource(e.target.value)} placeholder="يدوي / HAYO Bot / ..." className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500/50 text-sm" />
          </div>

          <div className="flex gap-3 pt-2">
            <Button type="button" variant="ghost" onClick={onClose} className="flex-1 text-gray-400">إلغاء</Button>
            <Button type="submit" disabled={addTrade.isPending} className="flex-1 bg-gradient-to-r from-emerald-600 to-green-700 hover:from-emerald-700 hover:to-green-800 text-white">
              {addTrade.isPending ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />} إضافة الصفقة
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────
export default function TradingBrokers() {
  const { user, isLoading: authLoading } = useAuth();
  const [showAddAccount, setShowAddAccount] = useState(false);
  const [showAddTrade, setShowAddTrade] = useState<number | null>(null);
  const [expandedAccount, setExpandedAccount] = useState<number | null>(null);

  const accounts = trpc.hayo.broker.listAccounts.useQuery(undefined, { enabled: !!user });
  const stats = trpc.hayo.broker.getStats.useQuery(undefined, { enabled: !!user });
  const trades = trpc.hayo.broker.listTrades.useQuery({ limit: 100 }, { enabled: !!user });
  const deleteMutation = trpc.hayo.broker.deleteAccount.useMutation({
    onSuccess: () => { toast.success("تم حذف الحساب"); accounts.refetch(); stats.refetch(); trades.refetch(); },
    onError: (err) => toast.error(err.message),
  });

  if (authLoading) return (
    <div className="min-h-screen bg-[#0a0c10] flex items-center justify-center">
      <Loader2 className="size-8 animate-spin text-blue-500" />
    </div>
  );

  if (!user) {
    window.location.href = getLoginUrl();
    return null;
  }

  const refetchAll = () => { accounts.refetch(); stats.refetch(); trades.refetch(); };

  const statsData = stats.data ?? { total: 0, wins: 0, losses: 0, winRate: 0, totalPnl: 0 };
  const accountList = accounts.data ?? [];
  const tradeList = trades.data ?? [];

  return (
    <div className="min-h-screen bg-[#0a0c10] text-white" dir="rtl">
      {/* Header */}
      <header className="sticky top-0 z-40 bg-[#0a0c10]/90 backdrop-blur-xl border-b border-white/5 px-4 py-3">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/dashboard">
              <Button variant="ghost" size="icon" className="text-gray-400 hover:text-white">
                <Home className="size-4" />
              </Button>
            </Link>
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-emerald-500 to-green-600 flex items-center justify-center">
                <BarChart3 className="size-4 text-white" />
              </div>
              <div>
                <h1 className="text-sm font-bold text-white">منصات التداول</h1>
                <p className="text-xs text-gray-500">إدارة حسابات التداول الثنائي</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" onClick={refetchAll} className="text-gray-400 hover:text-white">
              <RefreshCw className={`size-4 ${accounts.isFetching ? "animate-spin" : ""}`} />
            </Button>
            <Button
              onClick={() => setShowAddAccount(true)}
              className="bg-gradient-to-r from-emerald-600 to-green-700 hover:from-emerald-700 hover:to-green-800 text-white text-sm px-4 py-2 rounded-xl flex items-center gap-2"
            >
              <Plus className="size-4" /> ربط حساب
            </Button>
            <LanguageSwitcher />
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        {/* Stats Bar */}
        {stats.data && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "إجمالي الصفقات", value: statsData.total, icon: Activity, color: "text-blue-400", bg: "bg-blue-500/10" },
              { label: "نسبة الفوز", value: `${statsData.winRate}%`, icon: Target, color: "text-emerald-400", bg: "bg-emerald-500/10" },
              { label: "رابح / خاسر", value: `${statsData.wins} / ${statsData.losses}`, icon: BarChart3, color: "text-purple-400", bg: "bg-purple-500/10" },
              {
                label: "إجمالي الربح/الخسارة",
                value: `${statsData.totalPnl >= 0 ? "+" : ""}${statsData.totalPnl}$`,
                icon: DollarSign,
                color: statsData.totalPnl >= 0 ? "text-emerald-400" : "text-red-400",
                bg: statsData.totalPnl >= 0 ? "bg-emerald-500/10" : "bg-red-500/10",
              },
            ].map(({ label, value, icon: Icon, color, bg }) => (
              <div key={label} className={`${bg} border border-white/10 rounded-xl p-4 flex items-center gap-3`}>
                <Icon className={`size-5 ${color} shrink-0`} />
                <div>
                  <p className="text-xs text-gray-400">{label}</p>
                  <p className={`text-lg font-bold ${color}`}>{value}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Accounts */}
        <div>
          <h2 className="text-base font-bold text-white mb-3 flex items-center gap-2">
            <Wallet className="size-4 text-blue-400" /> الحسابات المرتبطة ({accountList.length})
          </h2>

          {accounts.isLoading ? (
            <div className="flex justify-center py-12"><Loader2 className="size-6 animate-spin text-gray-500" /></div>
          ) : accountList.length === 0 ? (
            <div className="border border-dashed border-white/10 rounded-2xl p-12 text-center">
              <Wallet className="size-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 text-lg font-medium mb-2">لا توجد حسابات مرتبطة</p>
              <p className="text-gray-500 text-sm mb-6">اربط حساب التداول الخاص بك لتتبع صفقاتك وإحصائياتك</p>
              <Button onClick={() => setShowAddAccount(true)} className="bg-gradient-to-r from-emerald-600 to-green-700 text-white px-6 py-2.5 rounded-xl flex items-center gap-2 mx-auto">
                <Plus className="size-4" /> ربط أول حساب
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {accountList.map((account) => {
                const cfg = PLATFORMS[account.platform as Platform];
                const accountTrades = tradeList.filter(t => t.brokerAccountId === account.id);
                const accountWins = accountTrades.filter(t => t.result === "win").length;
                const accountLosses = accountTrades.filter(t => t.result === "loss").length;
                const isExpanded = expandedAccount === account.id;

                return (
                  <div key={account.id} className={`border rounded-2xl overflow-hidden transition-all ${cfg.border} ${cfg.bg}`}>
                    <div
                      className="flex items-center gap-4 p-4 cursor-pointer"
                      onClick={() => setExpandedAccount(isExpanded ? null : account.id)}
                    >
                      <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${cfg.color} flex items-center justify-center text-white font-bold text-lg shrink-0`}>
                        {cfg.logo}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-white">{account.accountName || cfg.name}</h3>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${cfg.bg} ${cfg.text} border ${cfg.border}`}>{cfg.name}</span>
                          {account.isActive && <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">● نشط</span>}
                        </div>
                        {account.accountEmail && <p className="text-xs text-gray-500 mt-0.5">{account.accountEmail}</p>}
                        <div className="flex items-center gap-3 mt-1">
                          {account.balance && (
                            <span className="text-sm text-gray-300 flex items-center gap-1">
                              <DollarSign className="size-3 text-gray-500" />
                              {parseFloat(account.balance).toLocaleString()} {account.currency}
                            </span>
                          )}
                          <span className="text-xs text-gray-500">{accountTrades.length} صفقة • {accountWins}✓ {accountLosses}✗</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Button
                          size="sm"
                          onClick={(e) => { e.stopPropagation(); setShowAddTrade(account.id); }}
                          className="bg-white/5 hover:bg-white/10 text-white text-xs px-3 py-1.5 rounded-lg border border-white/10 flex items-center gap-1"
                        >
                          <Plus className="size-3" /> صفقة
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (confirm("حذف هذا الحساب وجميع صفقاته؟")) deleteMutation.mutate({ id: account.id });
                          }}
                          className="text-red-400 hover:text-red-300 hover:bg-red-500/10 size-8"
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                        {isExpanded ? <ChevronUp className="size-4 text-gray-400" /> : <ChevronDown className="size-4 text-gray-400" />}
                      </div>
                    </div>

                    {/* Expanded trades for this account */}
                    {isExpanded && (
                      <div className="border-t border-white/5 p-4">
                        {accountTrades.length === 0 ? (
                          <p className="text-center text-gray-500 text-sm py-4">لا توجد صفقات مسجلة لهذا الحساب</p>
                        ) : (
                          <div className="space-y-2 max-h-60 overflow-y-auto">
                            {accountTrades.slice(0, 20).map((trade) => {
                              const resCfg = RESULT_CONFIG[trade.result];
                              const ResIcon = resCfg.icon;
                              return (
                                <div key={trade.id} className="flex items-center gap-3 p-2.5 bg-white/3 rounded-xl">
                                  <span className={`text-xs px-2 py-1 rounded-lg ${trade.direction === "call" ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}`}>
                                    {trade.direction === "call" ? "▲ CALL" : "▼ PUT"}
                                  </span>
                                  <span className="text-sm text-white font-medium">{trade.asset}</span>
                                  <span className="text-xs text-gray-400">${parseFloat(trade.amount).toFixed(2)}</span>
                                  <span className="text-xs text-gray-500">{trade.durationSeconds < 60 ? `${trade.durationSeconds}ث` : `${trade.durationSeconds / 60}د`}</span>
                                  <div className={`flex items-center gap-1 text-xs ${resCfg.color} mr-auto`}>
                                    <ResIcon className="size-3.5" />
                                    {resCfg.text}
                                    {trade.profitLoss && (
                                      <span className={`font-mono ${parseFloat(trade.profitLoss) >= 0 ? "text-emerald-400" : "text-red-400"}`}>
                                        {parseFloat(trade.profitLoss) >= 0 ? "+" : ""}{parseFloat(trade.profitLoss).toFixed(2)}$
                                      </span>
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Trades Table */}
        {tradeList.length > 0 && (
          <div>
            <h2 className="text-base font-bold text-white mb-3 flex items-center gap-2">
              <Activity className="size-4 text-purple-400" /> آخر الصفقات
            </h2>
            <div className="bg-white/3 border border-white/10 rounded-2xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className="text-right text-gray-400 font-medium px-4 py-3">المنصة</th>
                      <th className="text-right text-gray-400 font-medium px-4 py-3">الأصل</th>
                      <th className="text-right text-gray-400 font-medium px-4 py-3">الاتجاه</th>
                      <th className="text-right text-gray-400 font-medium px-4 py-3">المبلغ</th>
                      <th className="text-right text-gray-400 font-medium px-4 py-3">المدة</th>
                      <th className="text-right text-gray-400 font-medium px-4 py-3">النتيجة</th>
                      <th className="text-right text-gray-400 font-medium px-4 py-3">ر/خ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tradeList.slice(0, 30).map((trade) => {
                      const account = accountList.find(a => a.id === trade.brokerAccountId);
                      const platformCfg = account ? PLATFORMS[account.platform as Platform] : null;
                      const resCfg = RESULT_CONFIG[trade.result];
                      const ResIcon = resCfg.icon;
                      return (
                        <tr key={trade.id} className="border-b border-white/5 hover:bg-white/3 transition-colors">
                          <td className="px-4 py-2.5">
                            {platformCfg ? (
                              <span className={`text-xs ${platformCfg.text}`}>{platformCfg.name}</span>
                            ) : <span className="text-gray-500 text-xs">—</span>}
                          </td>
                          <td className="px-4 py-2.5 text-white font-medium">{trade.asset}</td>
                          <td className="px-4 py-2.5">
                            <span className={`text-xs px-2 py-1 rounded-lg ${trade.direction === "call" ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}`}>
                              {trade.direction === "call" ? "▲ CALL" : "▼ PUT"}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-gray-300 font-mono">${parseFloat(trade.amount).toFixed(2)}</td>
                          <td className="px-4 py-2.5 text-gray-400">{trade.durationSeconds < 60 ? `${trade.durationSeconds}ث` : `${trade.durationSeconds / 60}د`}</td>
                          <td className="px-4 py-2.5">
                            <span className={`flex items-center gap-1 text-xs ${resCfg.color}`}>
                              <ResIcon className="size-3.5" /> {resCfg.text}
                            </span>
                          </td>
                          <td className={`px-4 py-2.5 font-mono text-sm ${trade.profitLoss ? (parseFloat(trade.profitLoss) >= 0 ? "text-emerald-400" : "text-red-400") : "text-gray-500"}`}>
                            {trade.profitLoss ? `${parseFloat(trade.profitLoss) >= 0 ? "+" : ""}${parseFloat(trade.profitLoss).toFixed(2)}$` : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Info Banner */}
        <div className="flex items-start gap-3 p-4 bg-blue-500/5 border border-blue-500/20 rounded-xl">
          <AlertTriangle className="size-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="text-sm text-gray-400">
            <p className="font-medium text-blue-300 mb-1">ملاحظة هامة</p>
            <p>هذه الصفحة لتتبع صفقاتك يدوياً وقياس أداء إشارات HAYO. التداول الآلي المباشر مع المنصات يتطلب إعداد إضافي. تأكد من اتباع قواعد إدارة رأس المال وعدم المخاطرة بأكثر مما تتحمل.</p>
          </div>
        </div>
      </div>

      {/* Modals */}
      {showAddAccount && (
        <AddAccountModal onClose={() => setShowAddAccount(false)} onSuccess={refetchAll} />
      )}
      {showAddTrade !== null && (
        <AddTradeModal accountId={showAddTrade} onClose={() => setShowAddTrade(null)} onSuccess={refetchAll} />
      )}
    </div>
  );
}
