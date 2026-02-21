"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import {
  LayoutDashboard,
  GitPullRequest,
  Wallet,
  ShieldCheck,
  Shield,
  Brain,
  Fingerprint,
  Coins,
  Search,
  ScrollText,
  Settings,
  Command,
} from "lucide-react";

const pages = [
  { label: "Overview", href: "/", icon: LayoutDashboard, keywords: "dashboard home" },
  { label: "Pipeline Feed", href: "/pipeline", icon: GitPullRequest, keywords: "reviews pr" },
  { label: "Treasury", href: "/treasury", icon: Wallet, keywords: "balance budget" },
  { label: "Verification", href: "/verification", icon: ShieldCheck, keywords: "windows challenges" },
  { label: "Disputes", href: "/verification/disputes", icon: ShieldCheck, keywords: "challenge dispute" },
  { label: "Patrol", href: "/patrol", icon: Shield, keywords: "security vulnerabilities" },
  { label: "Intelligence", href: "/intelligence", icon: Brain, keywords: "patterns stats" },
  { label: "Knowledge", href: "/intelligence/knowledge", icon: Brain, keywords: "codebase files" },
  { label: "Attestation", href: "/attestation", icon: Fingerprint, keywords: "proof tee" },
  { label: "Staking", href: "/staking", icon: Coins, keywords: "contributors stake" },
  { label: "Audit", href: "/audit", icon: Search, keywords: "paid audit" },
  { label: "Logs", href: "/logs", icon: ScrollText, keywords: "system events" },
  { label: "Settings", href: "/settings", icon: Settings, keywords: "config vision identity" },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const navigate = useCallback(
    (href: string) => {
      setOpen(false);
      router.push(href);
    },
    [router],
  );

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Search pages, reviews, attestations..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        <CommandGroup heading="Pages">
          {pages.map((page) => {
            const Icon = page.icon;
            return (
              <CommandItem
                key={page.href}
                value={`${page.label} ${page.keywords}`}
                onSelect={() => navigate(page.href)}
              >
                <Icon className="mr-2 h-4 w-4" />
                {page.label}
              </CommandItem>
            );
          })}
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="Actions">
          <CommandItem
            value="keyboard shortcuts help"
            onSelect={() => {
              setOpen(false);
              // Could open a shortcuts dialog
            }}
          >
            <Command className="mr-2 h-4 w-4" />
            Keyboard Shortcuts
            <span className="ml-auto text-xs text-muted-foreground">?</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}

export function CommandPaletteTrigger() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="hidden md:flex items-center gap-2 text-muted-foreground h-8 px-3"
        onClick={() => setOpen(true)}
        aria-label="Open command palette"
      >
        <Search className="h-3.5 w-3.5" />
        <span className="text-xs">Search...</span>
        <kbd className="pointer-events-none ml-2 inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
          <span className="text-xs">⌘</span>K
        </kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Search pages, reviews, attestations..." />
        <CommandList>
          <CommandEmpty>No results found.</CommandEmpty>
          <CommandGroup heading="Pages">
            {pages.map((page) => {
              const Icon = page.icon;
              return (
                <CommandItem
                  key={page.href}
                  value={`${page.label} ${page.keywords}`}
                  onSelect={() => {
                    setOpen(false);
                    window.location.href = page.href;
                  }}
                >
                  <Icon className="mr-2 h-4 w-4" />
                  {page.label}
                </CommandItem>
              );
            })}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}
