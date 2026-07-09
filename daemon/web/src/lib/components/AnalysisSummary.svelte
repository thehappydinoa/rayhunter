<script lang="ts">
    import { AnalysisRowType, type AnalysisReport, type EventType } from '$lib/analysis.svelte';

    let {
        report,
        current,
    }: {
        report: AnalysisReport;
        current: boolean;
    } = $props();

    type WarningGroup = {
        analyzer_name: string;
        event_type: EventType;
        messages: string[];
    };

    const warning_groups: WarningGroup[] = $derived.by(() => {
        const groups = new Map<string, WarningGroup>();
        const analyzers = report.metadata?.analyzers;
        if (!analyzers || !report.rows) return [];

        for (const row of report.rows) {
            if (row.type !== AnalysisRowType.Analysis) continue;
            for (let i = 0; i < row.events.length; i++) {
                const event = row.events[i];
                if (event === null || event.event_type === 'Informational') continue;
                const analyzer = analyzers[i];
                if (!analyzer) continue;
                const key = analyzer.name;
                if (!groups.has(key)) {
                    groups.set(key, {
                        analyzer_name: analyzer.name,
                        event_type: event.event_type,
                        messages: [],
                    });
                }
                const group = groups.get(key)!;
                // Keep the highest severity
                const severity_order: EventType[] = ['Low', 'Medium', 'High'];
                if (
                    severity_order.indexOf(event.event_type) >
                    severity_order.indexOf(group.event_type)
                ) {
                    group.event_type = event.event_type;
                }
                group.messages.push(event.message);
            }
        }
        return Array.from(groups.values());
    });

    const max_severity: EventType | 'None' = $derived.by(() => {
        if (warning_groups.length === 0) return 'None';
        const severity_order: EventType[] = ['Low', 'Medium', 'High'];
        let max: EventType = 'Low';
        for (const group of warning_groups) {
            if (severity_order.indexOf(group.event_type) > severity_order.indexOf(max)) {
                max = group.event_type;
            }
        }
        return max;
    });

    /**
     * Returns a plain-English explanation for a given analyzer warning group.
     */
    function explain_warning(group: WarningGroup): string {
        const name = group.analyzer_name.toLowerCase();

        if (name.includes('attach reject storm') || name.includes('attach/tau reject')) {
            if (group.messages.some((m) => m.toLowerCase().includes('plmn not allowed'))) {
                return "Your phone received a burst of rejection messages from a cell tower saying your carrier isn't allowed. This most likely means you're roaming or your SIM isn't provisioned for this network — not an attack. However, a fake tower could also spam these rejections to force your phone to keep reconnecting, exposing your identity each time.";
            }
            return 'Your phone received a rapid burst of rejection messages from a nearby tower. A real tower occasionally sends one, but many in a row can indicate a fake cell tower trying to force your phone to reveal its identity repeatedly.';
        }
        if (name.includes('null cipher')) {
            return "A tower is communicating with your phone without encryption. This means your calls and texts on this connection could be intercepted. Legitimate networks sometimes do this briefly, but it's a strong red flag if it persists.";
        }
        if (name.includes('nas null cipher')) {
            return 'The network explicitly asked your phone to disable encryption. This is suspicious — legitimate networks rarely do this, and it could allow someone to eavesdrop on your communications.';
        }
        if (name.includes('imsi') && name.includes('requested')) {
            return "A tower asked your phone to reveal its permanent identity (IMSI) without a normal reason like attaching to the network. This is the classic signature of an IMSI catcher — a device that collects the unique identifiers of nearby phones to track who's in an area.";
        }
        if (name.includes('2g downgrade') || name.includes('sib 6/7')) {
            return 'A tower is trying to push your phone onto a 2G connection. 2G has much weaker security and is easier to intercept. Fake towers often force this downgrade so they can eavesdrop more easily.';
        }
        if (name.includes('incomplete sib')) {
            return "A tower is broadcasting incomplete system information. Real towers include full details about the network; an incomplete broadcast can indicate a hastily-configured fake tower that didn't bother to set up everything properly.";
        }
        if (name.includes('missing authentication') || name.includes('security mode')) {
            return "A tower enabled encryption without first proving its identity to your phone. Legitimate towers authenticate themselves before starting encrypted communication. Skipping this step is a hallmark of fake towers — they can't authenticate because they don't have the real network's secret keys.";
        }
        if (name.includes('silent sms') || name.includes('type-0')) {
            return 'Your phone received an invisible "silent" text message. These are used to ping your phone without you knowing — confirming you\'re in range of a particular tower. Law enforcement and surveillance operators use these to track targets.';
        }
        if (name.includes('imsi paging') || name.includes('presence test')) {
            return "The network paged your phone using its permanent identity (IMSI) instead of the temporary one it normally uses. This is a strong sign of a presence test — someone checking whether you're specifically in this area.";
        }
        // Fallback for any unknown analyzer
        return `The "${group.analyzer_name}" detector flagged suspicious activity. Check the details below for more information.`;
    }

    function overall_message(): string {
        if (max_severity === 'None') {
            if (current) {
                return 'Everything looks normal so far. Rayhunter is actively monitoring your cellular connection and has not detected anything suspicious.';
            }
            return 'This recording looks clean. No suspicious cellular activity was detected.';
        }
        if (max_severity === 'Low') {
            return "Rayhunter noticed some mildly unusual cellular behavior. This is probably normal network activity, but it's worth being aware of.";
        }
        if (max_severity === 'Medium') {
            return "Rayhunter detected activity that could indicate a fake cell tower nearby, but it could also have an innocent explanation. Read the details below to understand what was seen.";
        }
        return 'Rayhunter detected behavior that is a strong indicator of a fake cell tower or surveillance device nearby. Consider moving to a different location and see if the warnings stop.';
    }

    const overall_style = $derived(
        {
            None: 'bg-green-50 border-green-300 text-green-900',
            Informational: 'bg-green-50 border-green-300 text-green-900',
            Low: 'bg-yellow-50 border-yellow-300 text-yellow-900',
            Medium: 'bg-orange-50 border-orange-300 text-orange-900',
            High: 'bg-red-50 border-red-400 text-red-900',
        }[max_severity],
    );

    const overall_icon = $derived(
        {
            None: '✓',
            Informational: '✓',
            Low: '○',
            Medium: '⚠',
            High: '⚠',
        }[max_severity],
    );
</script>

<div class="flex flex-col gap-3">
    <!-- Overall status -->
    <div class="border rounded-lg p-4 {overall_style}">
        <p class="text-lg font-semibold mb-1">
            {overall_icon}
            {#if max_severity === 'None'}
                No issues detected
            {:else if max_severity === 'Low'}
                Minor activity noted
            {:else if max_severity === 'Medium'}
                Possibly suspicious activity
            {:else}
                Suspicious activity detected
            {/if}
        </p>
        <p>{overall_message()}</p>
    </div>

    <!-- Per-warning explanations -->
    {#if warning_groups.length > 0}
        <div class="flex flex-col gap-2">
            <p class="font-semibold">What was detected:</p>
            {#each warning_groups as group}
                {@const border_class = {
                    Informational: 'border-l-gray-300',
                    Low: 'border-l-yellow-400',
                    Medium: 'border-l-orange-400',
                    High: 'border-l-red-500',
                }[group.event_type]}
                <div class="border-l-4 {border_class} pl-3 py-1">
                    <p class="font-medium">{group.analyzer_name}</p>
                    <p class="text-sm mt-1">{explain_warning(group)}</p>
                </div>
            {/each}
        </div>
    {/if}
</div>
