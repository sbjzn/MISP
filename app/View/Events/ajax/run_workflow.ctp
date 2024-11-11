

<?php
$fields = [];
if (!empty($workflows)) {
    foreach ($workflows as $wf) {
        $wf = $wf['Workflow'];
        $fields[] = [
            'field' => $wf['id'],
            'label' => sprintf('%s :: %s', h($wf['trigger_id']), h($wf['name'])),
            'type' => 'checkbox',
        ];
    }
}

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Select the workflow(s) you wish to run on the selected Event'),
        'model' => 'Event',
        'title' => __('Run Workflows on Event'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
        ]
    ]
]);
