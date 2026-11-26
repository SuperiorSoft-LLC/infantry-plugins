// \0infantry-lent:react
var e = globalThis.__INFANTRY_UI_HOST__;
if (!e) throw Error("react: no Infantry AI app on this page (a web UI plugin runs inside the app)");
var t = e.modules.react;
t && "default" in t && t.default;
var { Activity: n, Children: r, Component: i, Fragment: a, Profiler: o, PureComponent: s, StrictMode: c, Suspense: l, ViewTransition: u, __CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE: d, __COMPILER_RUNTIME: ee, act: te, addTransitionType: ne, cache: re, cacheSignal: ie, captureOwnerStack: ae, cloneElement: oe, createContext: se, createElement: ce, createRef: le, forwardRef: ue, isValidElement: de, lazy: fe, memo: f, startTransition: p, unstable_useCacheRefresh: m, use: h, useActionState: g, useCallback: _, useContext: v, useDebugValue: pe, useDeferredValue: me, useEffect: y, useEffectEvent: he, useId: ge, useImperativeHandle: _e, useInsertionEffect: ve, useLayoutEffect: ye, useMemo: be, useOptimistic: xe, useReducer: Se, useRef: b, useState: x, useSyncExternalStore: S, useTransition: C, version: w } = t, T = {
	apiVersion: 1,
	global: "__INFANTRY_UI_HOST__",
	scopeAttribute: "data-ui-plugin",
	modules: [
		"react",
		"react/jsx-runtime",
		"react-dom",
		"@infantry/ui"
	]
}, E = T.apiVersion, D = T.global;
T.scopeAttribute, T.modules;
// .infantry-ai/app/packages/client/src/wire.ts
var O = {
	READY: "ready",
	POLICY: "policy",
	PROMPT: "prompt",
	STDOUT: "stdout",
	STDERR: "stderr",
	EXIT: "exit",
	ERROR: "error",
	SESSION: "session",
	SESSIONS: "sessions",
	KILL: "kill",
	INTERRUPT: "interrupt",
	QUEUE_ADD: "queue_add",
	QUEUE_REMOVE: "queue_remove",
	QUEUE_FORCE: "queue_force",
	PROMPT_ACK: "prompt_ack",
	NEW: "new",
	ASSISTANT: "assistant",
	TEXT_DELTA: "text_delta",
	STATUS: "status",
	FINISHED: "finished",
	TURN: "turn",
	REASONING: "reasoning",
	REPLAY_REQUEST: "replay_request",
	REPLAY_GAP: "replay_gap",
	USAGE: "usage",
	AGENT_LIST: "agent_list",
	AGENTS: "agents",
	AGENT: "agent",
	TICKET_LIST: "ticket_list",
	TICKET_GET: "ticket_get",
	TICKETS: "tickets",
	TICKET: "ticket",
	PROJECT_LIST: "project_list",
	PROJECTS: "projects",
	PROJECT: "project"
};
O.SESSION, O.STATUS, O.TURN, O.TEXT_DELTA, O.REASONING, O.STDOUT, O.STDERR, O.ERROR, O.FINISHED, O.EXIT, O.USAGE;
function k(e) {
	try {
		return JSON.parse(e);
	} catch {
		return null;
	}
}
var A = "runner_frame", j = 0, M = (e) => !e || e === "local";
function N(e, t) {
	return M(e) ? t : {
		...t,
		type: A,
		data: JSON.stringify({
			runner: e,
			frame: t.type,
			data: t.data
		})
	};
}
function P(e, t, n, r = "{}", i = 3e4) {
	return new Promise((a, o) => {
		j += 1;
		let s = `rreq:${Date.now().toString(36)}-${j.toString(36)}`, c = (e) => {
			clearTimeout(u), l(), e();
		}, l = e.onFrame((e) => {
			e.requestId === s && (e.type === "error" ? c(() => o(Error(e.data))) : c(() => a(e)));
		}), u = setTimeout(() => c(() => o(/* @__PURE__ */ Error(`${n}: no answer from runner ${t || "local"}`))), i);
		e.sendFrame(N(t, {
			type: n,
			data: r,
			requestId: s
		})) || c(() => o(/* @__PURE__ */ Error(`${n} not sent: the daemon link is down`)));
	});
}
// .infantry-ai/app/packages/ui-plugin-api/src/index.ts
function F() {
	let e = globalThis[D];
	if (!e) throw Error("@infantry/ui-plugin-api: no Infantry AI app on this page (a web UI plugin runs inside the app)");
	return e;
}
function I(e) {
	return e;
}
function L(e) {
	let t = F().api.openExternal;
	t ? t(e).catch(() => void 0) : window.open(e, "_blank", "noopener,noreferrer");
}
var R = /* @__PURE__ */ new Map();
function z(e, t, n) {
	let [r, i] = x(null);
	return y(() => {
		if (i(null), !n || !/^https:\/\//i.test(n)) return;
		let r = `${t} ${n}`, a = R.get(r);
		a || (a = P(e, null, "card_image", JSON.stringify({
			type: t,
			url: n
		}), 3e4).then((e) => {
			let t = k(e.data);
			return t?.ok && t.mime && t.base64 ? `data:${t.mime};base64,${t.base64}` : null;
		}).catch(() => null), R.set(r, a));
		let o = !0;
		return a.then((e) => o && i(e)), () => {
			o = !1;
		};
	}, [
		e,
		t,
		n
	]), r;
}
// \0infantry-lent:@infantry/ui
var B = globalThis.__INFANTRY_UI_HOST__;
if (!B) throw Error("@infantry/ui: no Infantry AI app on this page (a web UI plugin runs inside the app)");
var V = B.modules["@infantry/ui"];
V && "default" in V && V.default;
var { AppDialog: Ce, Avatar: we, AvatarBadge: Te, AvatarFallback: Ee, AvatarGroup: De, AvatarGroupCount: Oe, AvatarImage: ke, Badge: Ae, Button: je, Card: Me, CardAction: Ne, CardContent: Pe, CardDescription: Fe, CardFooter: Ie, CardHeader: Le, CardTitle: Re, Chip: ze, DIALOG_WIDTHS: Be, Dialog: Ve, DialogClose: He, DialogContent: Ue, DialogDescription: We, DialogFooter: Ge, DialogHeader: Ke, DialogOverlay: qe, DialogPortal: Je, DialogTitle: Ye, DialogTrigger: Xe, DropdownMenu: Ze, DropdownMenuCheckboxItem: Qe, DropdownMenuContent: $e, DropdownMenuGroup: et, DropdownMenuItem: tt, DropdownMenuLabel: nt, DropdownMenuPortal: rt, DropdownMenuRadioGroup: it, DropdownMenuRadioItem: at, DropdownMenuSeparator: H, DropdownMenuShortcut: ot, DropdownMenuSub: st, DropdownMenuSubContent: ct, DropdownMenuSubTrigger: lt, DropdownMenuTrigger: ut, EmptyState: dt, Field: ft, IconButton: pt, Input: mt, KeyHint: ht, Label: gt, ListRow: _t, MeterBar: vt, PanelCard: yt, PortalContainer: bt, Progress: xt, ProgressLine: St, RefusalBanner: Ct, ScrollArea: wt, ScrollBar: Tt, SectionLabel: Et, SegmentedBar: Dt, Select: Ot, SelectContent: kt, SelectGroup: At, SelectItem: jt, SelectLabel: Mt, SelectScrollDownButton: Nt, SelectScrollUpButton: Pt, SelectSeparator: Ft, SelectTrigger: It, SelectValue: Lt, SelectedStripes: Rt, Separator: zt, StatusDot: Bt, Switch: Vt, TabPage: Ht, Tabs: Ut, TabsContent: Wt, TabsList: Gt, TabsTrigger: Kt, Textarea: qt, Toggle: Jt, ToggleGroup: Yt, ToggleGroupItem: Xt, Tooltip: Zt, TooltipContent: Qt, TooltipProvider: $t, TooltipTrigger: en, ago: U, badgeVariants: tn, buttonVariants: nn, cn: W, meterTone: rn, tabsListVariants: an, toggleVariants: on, usePortalContainer: sn } = V, G = (e) => typeof e == "string" && e.trim() ? e.trim() : void 0;
function K(e) {
	return (Array.isArray(e.items) ? e.items : []).flatMap((e) => {
		if (!e || typeof e != "object") return [];
		let t = e, n = G(t.title), r = G(t.url);
		return !n || !r || !/^https?:\/\//i.test(r) ? [] : [{
			title: n,
			url: r,
			source: G(t.source),
			time: G(t.time),
			image: G(t.image),
			icon: G(t.icon)
		}];
	});
}
// \0infantry-lent:react/jsx-runtime
var q = globalThis.__INFANTRY_UI_HOST__;
if (!q) throw Error("react/jsx-runtime: no Infantry AI app on this page (a web UI plugin runs inside the app)");
var J = q.modules["react/jsx-runtime"];
J && "default" in J && J.default;
var { Fragment: cn, jsx: Y, jsxs: X } = J;
// official/Infantry_News/ui/src/news-card.tsx
function Z({ link: e, h: t }) {
	let n = z(e, "news", t.image), r = z(e, "news", n ? null : t.icon), i = n ?? r;
	return i ? /* @__PURE__ */ Y("img", {
		src: i,
		alt: "",
		className: W("size-14 shrink-0 rounded-md border bg-muted", n ? "object-cover" : "object-contain p-2")
	}) : /* @__PURE__ */ Y("span", {
		"aria-hidden": !0,
		className: "grid size-14 shrink-0 place-items-center rounded-md border bg-muted text-lg font-semibold text-muted-foreground",
		children: (t.source ?? t.title).charAt(0).toUpperCase()
	});
}
function Q({ link: e, body: t }) {
	let n = K(t), r = G(t.title);
	return /* @__PURE__ */ X("div", {
		className: "rounded-lg border bg-card p-3 text-[13px]",
		"data-card": "news",
		children: [
			/* @__PURE__ */ Y("div", {
				className: "text-[10px] tracking-wide text-muted-foreground uppercase",
				children: "News"
			}),
			r && /* @__PURE__ */ Y("div", {
				className: "font-semibold",
				children: r
			}),
			n.length === 0 ? /* @__PURE__ */ Y("p", {
				className: "mt-1 text-muted-foreground",
				children: "No headlines."
			}) : /* @__PURE__ */ Y("ul", {
				className: "mt-2 grid gap-2",
				children: n.map((t, n) => {
					let r = t.time ? Date.parse(t.time) : NaN;
					return /* @__PURE__ */ Y("li", { children: /* @__PURE__ */ X("a", {
						href: t.url,
						onClick: (e) => {
							e.preventDefault(), L(t.url);
						},
						className: "flex items-start gap-3 rounded-md border p-2 hover:border-info/50",
						children: [/* @__PURE__ */ Y(Z, {
							link: e,
							h: t
						}), /* @__PURE__ */ X("span", {
							className: "min-w-0 flex-1",
							children: [/* @__PURE__ */ Y("span", {
								className: "line-clamp-2 font-medium text-foreground",
								children: t.title
							}), /* @__PURE__ */ Y("span", {
								className: "mt-0.5 block truncate text-xs text-muted-foreground",
								children: [t.source, Number.isFinite(r) ? `${U(r)} ago`.replace("now ago", "just now") : void 0].filter(Boolean).join(" · ")
							})]
						})]
					}) }, n);
				})
			})
		]
	});
}
// official/Infantry_News/ui/src/index.tsx
var $ = I({
	apiVersion: E,
	activate(e) {
		e.register("infantry.news.card", { render: ({ card: t }) => /* @__PURE__ */ Y(Q, {
			link: e.link,
			body: t.body
		}) });
	}
});
export { $ as default };
