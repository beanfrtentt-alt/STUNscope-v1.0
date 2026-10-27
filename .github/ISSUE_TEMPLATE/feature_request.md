name: Feature request
about: Suggest a protocol feature, filter, export option, or GUI improvement
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: What problem would this solve?
      description: Describe the workflow or analysis you are trying to do.
      placeholder: I want to filter Binding responses by ERROR-CODE value…
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: What would you like STUNScope to do?
      placeholder: Add an "error code" combo to the Filters page, and a --error-code CLI flag…
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives you considered
      placeholder: Exporting to CSV and filtering in a spreadsheet…
  - type: checkboxes
    id: scope
    attributes:
      label: Scope check
      options:
        - label: This is about analyzing authorized/owned network traffic, not about defeating privacy protections of calling apps.
          required: true
