<?php
    if (!empty($field['extendedEvent']) && is_array($field['extendedEvent'])) {
        echo sprintf(
            '<span>%s (<a href="%s">%s</a>): %s</span>',
            __('Event'),
            $baseurl . '/events/view/' . h($extendedEvent[0]['Event']['id']),
            h($extendedEvent[0]['Event']['id']),
            h($extendedEvent[0]['Event']['info'])
        );
        echo sprintf(
            '<a href="%s" style="margin-left: 0.5em;"><span class="fa fa-sync" title="%s"></span></a>',
            sprintf(
                '%s/events/view/%s%s',
                $baseurl,
                h($data['Event']['id']),
                ($field['extending'] ? '' : '/extending:1')
            ),
            $field['extending'] ? __('Switch to atomic view') : __('Switch to extending view')
        );
    } else {
        $value = Hash::extract($data, $field['path'])[0];
        echo h($value);
    }
