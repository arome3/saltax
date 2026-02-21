"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  LayoutDashboard,
  GitPullRequest,
  Wallet,
  ShieldCheck,
  Swords,
  Shield,
  Brain,
  BookOpen,
  Fingerprint,
  Coins,
  Search,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Menu,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetTrigger, SheetTitle } from "@/components/ui/sheet";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const navGroups = [
  {
    items: [
      { label: "Overview", href: "/", icon: LayoutDashboard },
    ],
  },
  {
    label: "Pipeline",
    items: [
      { label: "Review Feed", href: "/pipeline", icon: GitPullRequest },
    ],
  },
  {
    label: "Treasury",
    items: [
      { label: "Balance", href: "/treasury", icon: Wallet },
    ],
  },
  {
    label: "Verification",
    items: [
      { label: "Windows", href: "/verification", icon: ShieldCheck },
      { label: "Disputes", href: "/verification/disputes", icon: Swords },
    ],
  },
  {
    items: [
      { label: "Patrol", href: "/patrol", icon: Shield },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { label: "Stats", href: "/intelligence", icon: Brain },
      { label: "Knowledge", href: "/intelligence/knowledge", icon: BookOpen },
    ],
  },
  {
    items: [
      { label: "Attestation", href: "/attestation", icon: Fingerprint },
      { label: "Staking", href: "/staking", icon: Coins },
      { label: "Audit", href: "/audit", icon: Search },
      { label: "Logs", href: "/logs", icon: ScrollText },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
];

function NavContent({ collapsed }: { collapsed: boolean }) {
  const pathname = usePathname();

  return (
    <ScrollArea className="flex-1 py-2">
      <nav className="flex flex-col gap-1 px-2">
        {navGroups.map((group, gi) => (
          <div key={gi}>
            {group.label && !collapsed && (
              <span className="px-3 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                {group.label}
              </span>
            )}
            {group.label && collapsed && (
              <div className="mx-auto my-1 h-px w-6 bg-border" />
            )}
            {group.items.map((item) => {
              const isActive =
                item.href === "/"
                  ? pathname === "/"
                  : pathname.startsWith(item.href);
              const Icon = item.icon;

              const linkContent = (
                <Link
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                    "hover:bg-accent hover:text-accent-foreground",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                    isActive
                      ? "bg-accent text-accent-foreground font-medium"
                      : "text-muted-foreground",
                    collapsed && "justify-center px-2",
                  )}
                  aria-current={isActive ? "page" : undefined}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  {!collapsed && <span>{item.label}</span>}
                </Link>
              );

              if (collapsed) {
                return (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                    <TooltipContent side="right">{item.label}</TooltipContent>
                  </Tooltip>
                );
              }

              return <div key={item.href}>{linkContent}</div>;
            })}
          </div>
        ))}
      </nav>
    </ScrollArea>
  );
}

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <>
      {/* Desktop sidebar */}
      <aside
        className={cn(
          "hidden lg:flex flex-col border-r bg-sidebar text-sidebar-foreground transition-all duration-200",
          collapsed ? "w-16" : "w-60",
        )}
      >
        <div
          className={cn(
            "flex items-center border-b h-12 px-3",
            collapsed ? "justify-center" : "justify-between",
          )}
        >
          {!collapsed && (
            <span className="font-semibold text-sm tracking-tight">
              SaltaX
            </span>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </Button>
        </div>
        <NavContent collapsed={collapsed} />
      </aside>

      {/* Mobile sidebar */}
      <Sheet>
        <SheetTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden fixed top-2 left-2 z-50 h-9 w-9"
            aria-label="Open navigation"
          >
            <Menu className="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="w-60 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <div className="flex items-center border-b h-12 px-3">
            <span className="font-semibold text-sm tracking-tight">
              SaltaX
            </span>
          </div>
          <NavContent collapsed={false} />
        </SheetContent>
      </Sheet>
    </>
  );
}
