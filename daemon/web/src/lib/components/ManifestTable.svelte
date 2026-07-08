<script lang="ts">
    import { ManifestEntry } from '$lib/manifest.svelte';
    import { AnalysisManager } from '$lib/analysisManager.svelte';
    import { screenIsLgUp } from '$lib/stores/breakpoint';
    import TableRow from './ManifestTableRow.svelte';
    import Card from './ManifestCard.svelte';
    interface Props {
        entries: ManifestEntry[];
        server_is_recording: boolean;
        manager: AnalysisManager;
    }
    let { entries, server_is_recording, manager }: Props = $props();

    // Columns the table can be sorted by, mapped to the ManifestEntry field.
    type SortKey = 'name' | 'start_time' | 'last_message_time' | 'carrier' | 'qmdl_size_bytes';

    // No active sort by default: keep the server's reverse-chronological order.
    let sort_key = $state<SortKey | null>(null);
    let sort_dir = $state<'asc' | 'desc'>('desc');

    function toggle_sort(key: SortKey) {
        if (sort_key === key) {
            sort_dir = sort_dir === 'asc' ? 'desc' : 'asc';
        } else {
            sort_key = key;
            // A freshly-picked column starts descending (largest / newest
            // first), which is the usual intent for size and timestamps.
            sort_dir = 'desc';
        }
    }

    function compare(a: ManifestEntry, b: ManifestEntry, key: SortKey): number {
        switch (key) {
            case 'qmdl_size_bytes':
                return a.qmdl_size_bytes - b.qmdl_size_bytes;
            case 'start_time':
                return a.start_time.getTime() - b.start_time.getTime();
            case 'last_message_time':
                return (
                    (a.last_message_time?.getTime() ?? 0) - (b.last_message_time?.getTime() ?? 0)
                );
            case 'name':
                return a.name.localeCompare(b.name, undefined, { numeric: true });
            case 'carrier':
                return (a.carrier ?? '').localeCompare(b.carrier ?? '');
        }
    }

    let sorted_entries = $derived.by(() => {
        if (sort_key === null) return entries;
        const key = sort_key;
        const dir = sort_dir === 'asc' ? 1 : -1;
        // Copy so we don't mutate the prop; ties keep their relative order.
        return [...entries].sort((a, b) => dir * compare(a, b, key));
    });

    function aria_sort(key: SortKey): 'ascending' | 'descending' | 'none' {
        if (sort_key !== key) return 'none';
        return sort_dir === 'asc' ? 'ascending' : 'descending';
    }
</script>

{#snippet sortable_header(label: string, key: SortKey)}
    <th class="p-2" scope="col" aria-sort={aria_sort(key)}>
        <button
            type="button"
            class="flex items-center gap-1 font-bold cursor-pointer hover:underline"
            onclick={() => toggle_sort(key)}
            title="Sort by {label}"
        >
            {label}
            <span class="inline-block w-3 text-xs" aria-hidden="true">
                {#if sort_key === key}{sort_dir === 'asc' ? '▲' : '▼'}{/if}
            </span>
        </button>
    </th>
{/snippet}

<!--For larger screens we use a table-->
{#if $screenIsLgUp}
    <table class="table-auto text-left table">
        <thead>
            <tr class="bg-gray-100 drop-shadow-sm">
                {@render sortable_header('ID', 'name')}
                {@render sortable_header('Started', 'start_time')}
                {@render sortable_header('Last Message', 'last_message_time')}
                {@render sortable_header('Carrier', 'carrier')}
                {@render sortable_header('Size', 'qmdl_size_bytes')}
                <th class="p-2" scope="col">Download</th>
                <th class="p-2" scope="col">Analysis</th>
                <th class="p-2" scope="col"></th>
            </tr>
        </thead>
        <tbody>
            {#each sorted_entries as entry, i}
                <TableRow {entry} current={false} {i} {manager} />
            {/each}
        </tbody>
    </table>
{:else}
    <!--For smaller screens we use cards-->
    <div class="flex flex-col gap-4">
        {#each sorted_entries as entry}
            <Card {entry} current={false} {server_is_recording} {manager} />
        {/each}
    </div>
{/if}
